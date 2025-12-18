import argparse
import datetime
import ipaddress
import os
import subprocess
import sys
import select
import platform
import shutil
from pathlib import Path

# --- CONFIGURATION ---
TARGET_KEYWORDS = ["chatgpt", "claude", "gemini"]

def get_tshark_path():
    try:
        uname = platform.uname().release.lower()
        is_wsl = "microsoft" in uname or "wsl" in uname
    except:
        is_wsl = False
    if is_wsl:
        win_paths = ["/mnt/c/Program Files/Wireshark/tshark.exe", "/mnt/d/Program Files/Wireshark/tshark.exe"]
        for p in win_paths:
            if os.path.exists(p): return p, True
    return "tshark", False

def wsl_to_windows_path(path_str):
    if path_str.startswith("/mnt/"):
        parts = path_str.split("/")
        if len(parts) > 3:
            return f"{parts[2].upper()}:\\{'\\'.join(parts[3:])}"
    return path_str

def format_timestamp(epoch):
    try: return datetime.datetime.fromtimestamp(float(epoch)).strftime("%H:%M:%S.%f")
    except: return epoch

def format_flags(flags_str):
    # Map Tshark flag strings to tcpdump characters
    if not flags_str: return "[.]"
    f = flags_str.upper()
    out = ""
    if 'SYN' in f: out += 'S'
    if 'PSH' in f: out += 'P'
    if 'FIN' in f: out += 'F'
    if 'RST' in f: out += 'R'
    if 'ACK' in f: out += '.'
    return f"[{out}]" if out else "[.]"

def build_command(tshark_bin, is_win_bin, network, interface, ssl_keys):
    cmd = [tshark_bin, "-l", "-n"]
    cmd.extend([
        "-T", "fields",
        # IP/Frame details
        "-e", "frame.time_epoch", "-e", "ip.dsfield", "-e", "ip.ttl", 
        "-e", "ip.id", "-e", "ip.flags", "-e", "ip.proto", "-e", "ip.len",
        # Src/Dst
        "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport",
        # TCP details
        "-e", "tcp.flags.str", "-e", "tcp.checksum", "-e", "tcp.seq", 
        "-e", "tcp.ack", "-e", "tcp.window_size_value", "-e", "tcp.len",
        # Detection fields
        "-e", "tls.handshake.extensions_server_name", 
        "-e", "http2.headers.authority", 
        "-e", "dns.qry.name",
        "-E", "separator=/t", "-E", "occurrence=f"
    ])
    
    if interface: cmd.extend(["-i", interface])
    if ssl_keys:
        final_key = wsl_to_windows_path(ssl_keys) if is_win_bin else ssl_keys
        cmd.extend(["-o", f"tls.keylog_file:{final_key}"])

    is_ipv6 = isinstance(network, ipaddress.IPv6Network)
    proto = "ip6" if is_ipv6 else "ip"
    if network.prefixlen == 0: base_filter = f"{proto}"
    else:
        addr = network.network_address.compressed if is_ipv6 else network.network_address
        base_filter = f"{proto} host {addr}" if network.num_addresses == 1 else f"{proto} net {network.with_prefixlen}"
        
    cmd.extend(["-f", base_filter])
    return cmd

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("ip_range", help="CIDR range")
    p.add_argument("-i", "--interface", help="Interface")
    p.add_argument("-o", "--outdir", default=".", help="Output directory")
    p.add_argument("-k", "--ssl-keys", help="SSL Keylog file")
    p.add_argument("-t", "--timeout", type=int, help="Timeout seconds")
    return p.parse_args()

def main():
    args = parse_args()
    tshark_bin, is_win_bin = get_tshark_path()
    
    try: network = ipaddress.ip_network(args.ip_range, strict=False)
    except ValueError: sys.exit("Invalid CIDR")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    
    final_outfile = outdir / f"capture_{timestamp}.txt"
    temp_outfile = outdir / f"temp_{timestamp}.tmp"

    # MEMORY: Track found LLM IPs
    # Format: { "1.2.3.4": "OPENAI", "5.6.7.8": "ANTHROPIC" }
    llm_ip_map = {}

    cmd = build_command(tshark_bin, is_win_bin, network, args.interface, args.ssl_keys)
    print(f"Executing: {' '.join(cmd)}")
    print("Capturing... (Press Ctrl+C to finish and generate report)")

    try:
        # Open temp file for raw packet logs
        with temp_outfile.open("w", buffering=1, encoding="utf-8") as f_temp:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            start_time = datetime.datetime.now().timestamp()
            
            try:
                while proc.poll() is None:
                    reads = [proc.stdout.fileno()]
                    ret = select.select(reads, [], [], 0.5)
                    
                    if reads[0] in ret[0]:
                        line = proc.stdout.readline()
                        if line:
                            parts = line.strip().split('\t')
                            parts += [""] * (20 - len(parts)) # Pad columns

                            # Extract key fields
                            epoch, tos, ttl, ip_id, ip_flags, proto, ip_len = parts[:7]
                            src, sport, dst, dport = parts[7:11]
                            t_flags, t_sum, t_seq, t_ack, t_win, t_len = parts[11:17]
                            
                            # Detection
                            names = (parts[17] + parts[18] + parts[19]).lower()
                            
                            # Check for LLM keywords
                            detected_name = None
                            for kw in TARGET_KEYWORDS:
                                if kw in names:
                                    detected_name = kw.upper()
                                    break
                            
                            # If detected, associate the REMOTE IP with the LLM
                            # We assume the user's IP is likely local, so we check both,
                            # but usually the destination of a 'Client Hello' (SNI) is the server.
                            if detected_name:
                                # Heuristic: If detecting via SNI/DNS, the Destination is likely the Server
                                if dst not in llm_ip_map and not ipaddress.ip_address(dst).is_private:
                                    llm_ip_map[dst] = detected_name
                                    print(f"[!] Found {detected_name} at {dst}")
                                
                                # If it's a response (src is public), map source
                                if src not in llm_ip_map and not ipaddress.ip_address(src).is_private:
                                    llm_ip_map[src] = detected_name

                            # --- TCPDUMP FORMATTING ---
                            # Line 1
                            ts_str = format_timestamp(epoch)
                            proto_str = "TCP (6)" if proto == "6" else f"Proto ({proto})"
                            line1 = (f"{ts_str} IP (tos {tos or '0x0'}, ttl {ttl}, "
                                     f"id {ip_id}, offset 0, flags [{ip_flags or ''}], "
                                     f"proto {proto_str}, length {ip_len})")
                            
                            # Line 2
                            flags_fmt = format_flags(t_flags)
                            seq_str = f"seq {t_seq}" if t_seq else ""
                            ack_str = f"ack {t_ack}" if t_ack else ""
                            win_str = f"win {t_win}" if t_win else ""
                            
                            line2 = (f"    {src}.{sport} > {dst}.{dport}: Flags {flags_fmt}, "
                                     f"cksum {t_sum}, {seq_str}, {ack_str}, {win_str}, length {t_len}")
                            
                            # Write to temp file
                            f_temp.write(f"{line1}\n{line2}\n")

                    if args.timeout and (datetime.datetime.now().timestamp() >= start_time + args.timeout):
                        proc.terminate()
                        break
            except KeyboardInterrupt:
                proc.terminate()
                proc.wait()

        # --- PHASE 2: FINALIZE ---
        print("\nFinalizing capture file...")
        
        with final_outfile.open("w", encoding="utf-8") as f_final:
            # 1. Write the Headers
            if llm_ip_map:
                for ip, name in llm_ip_map.items():
                    f_final.write(f"LLM_IP {name} {ip}\n")
                f_final.write("\n") # Blank line separator
            else:
                f_final.write("# No LLM traffic detected.\n\n")

            # 2. Append the Packet Logs from Temp File
            with temp_outfile.open("r", encoding="utf-8") as f_temp:
                shutil.copyfileobj(f_temp, f_final)

        # Cleanup
        temp_outfile.unlink()
        print(f"Done. Output saved to: {final_outfile}")

    except Exception as e:
        sys.exit(f"Error: {e}")

if __name__ == "__main__":
    main()