import argparse
import datetime
import ipaddress
import os
import subprocess
import sys
import select
import platform
import binascii
import string
from pathlib import Path

# --- CONFIGURATION ---
# Keywords to auto-detect in Hostnames, SNI, or DNS queries
TARGET_KEYWORDS = ["chatgpt", "openai", "claude", "anthropic", "gemini", "bard", "meta.ai"]

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

def is_readable_text(s, threshold=0.90):
    if not s: return False
    allowed = set(string.printable)
    return (sum(1 for c in s if c in allowed) / len(s)) > threshold

def build_command(tshark_bin, is_win_bin, network, interface, ssl_keys, sniff_mode):
    cmd = [tshark_bin, "-l", "-n"]
    
    if sniff_mode:
        cmd.extend([
            "-T", "fields",
            "-e", "frame.time",                     # 0
            "-e", "ip.src",                         # 1
            "-e", "ip.dst",                         # 2
            "-e", "tcp.stream",                     # 3 (Stream ID)
            "-e", "_ws.col.Protocol",               # 4
            "-e", "frame.len",                      # 5
            "-e", "_ws.col.Info",                   # 6
            "-e", "http2.data.data",                # 7
            "-e", "http.file_data",                 # 8
            "-e", "tls.handshake.extensions_server_name", # 9 (SNI)
            "-e", "http2.headers.authority",        # 10 (HTTP2 Host)
            "-e", "http.host",                      # 11 (HTTP1 Host)
            "-e", "dns.qry.name",                   # 12 (DNS Query - NEW!)
            "-E", "separator=/t",
            "-E", "occurrence=f" # If multiple values exist, only take the first (cleaner output)
        ])
        # NO DISPLAY FILTER (-Y). We want to see EVERYTHING.
    else:
        pass

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
    p = argparse.ArgumentParser(description="Log all traffic, decrypt only LLMs.")
    p.add_argument("ip_range", help="IP range (0.0.0.0/0 for all)")
    p.add_argument("-i", "--interface", help="Interface name")
    p.add_argument("-o", "--outdir", default=".", help="Output directory")
    p.add_argument("-k", "--ssl-keys", help="Path to SSLKEYLOGFILE")
    p.add_argument("-t", "--timeout", type=int, help="Timeout seconds")
    p.add_argument("--sniff", action="store_true", help="Enable filtering")
    return p.parse_args()

def main():
    args = parse_args()
    tshark_bin, is_win_bin = get_tshark_path()
    
    try: network = ipaddress.ip_network(args.ip_range, strict=False)
    except ValueError: sys.exit("Invalid CIDR")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / f"hybrid_capture_{timestamp}.txt"
    
    target_streams = set()

    cmd = build_command(tshark_bin, is_win_bin, network, args.interface, args.ssl_keys, args.sniff)
    print(f"Executing: {' '.join(cmd)}")
    print(f"Decrypting content for keywords: {TARGET_KEYWORDS}")

    try:
        with outfile.open("w", buffering=1, encoding="utf-8") as f:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            start_time = datetime.datetime.now().timestamp()
            
            try:
                while proc.poll() is None:
                    reads = [proc.stdout.fileno()]
                    ret = select.select(reads, [], [], 0.5)
                    
                    if reads[0] in ret[0]:
                        line = proc.stdout.readline()
                        if line and args.sniff:
                            parts = line.strip().split('\t')
                            
                            # SAFE PARSING: Pad the list if Tshark returned fewer columns
                            required_len = 13
                            if len(parts) < required_len:
                                parts += [""] * (required_len - len(parts))

                            # Extract Columns
                            ts, src, dst, stream_id, proto, length, info = parts[:7]
                            data_hex = parts[7] or parts[8]
                            
                            # Combine all name fields for detection
                            # (SNI + HTTP2 Host + HTTP1 Host + DNS Query)
                            names = (parts[9] + parts[10] + parts[11] + parts[12]).lower()

                            # 1. ALWAYS LOG THE PACKET (Metadata)
                            # Only print to console if it's interesting, but always write to file
                            header_line = f"{ts} | {proto} | {src} -> {dst} | {info}"
                            f.write(header_line + "\n")
                            
                            # 2. DETECT TARGET
                            if any(k in names for k in TARGET_KEYWORDS):
                                # If we see a keyword in DNS or SNI, we might not have a stream ID yet (UDP/DNS)
                                # But if we DO have a stream ID (TCP), whitelist it.
                                if stream_id and stream_id not in target_streams:
                                    msg = f"\n[!!!] TARGET IDENTIFIED: {names} (Stream {stream_id})"
                                    print(msg) # Alert the user
                                    f.write(msg + "\n")
                                    target_streams.add(stream_id)
                            
                            # 3. DECRYPT CONTENT
                            if stream_id in target_streams and data_hex:
                                clean_hex = data_hex.replace(':', '')
                                try:
                                    decoded = binascii.unhexlify(clean_hex).decode('utf-8')
                                    if is_readable_text(decoded):
                                        f.write(f"    [LLM PAYLOAD]:\n    {decoded}\n    {'-'*60}\n")
                                        if any(c in decoded for c in "{<"):
                                            # Live Preview
                                            print(f"    [LLM Data]: {decoded[:100]}...")
                                except: pass
                        elif line:
                            f.write(line)

                    if args.timeout and (datetime.datetime.now().timestamp() >= start_time + args.timeout):
                        print("\n[!] Timeout.")
                        proc.terminate()
                        break
            except KeyboardInterrupt:
                proc.terminate()
                proc.wait()
    except Exception as e: sys.exit(f"Error: {e}")
    
    print(f"Capture complete. Check {outfile}")

if __name__ == "__main__":
    main()