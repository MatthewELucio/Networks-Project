import argparse
import datetime
import ipaddress
import os
import subprocess
import sys
import select
import platform
import binascii
import string  # <--- Added for text validation
from pathlib import Path

def get_tshark_path():
    try:
        uname = platform.uname().release.lower()
        is_wsl = "microsoft" in uname or "wsl" in uname
    except:
        is_wsl = False

    if is_wsl:
        win_paths = [
            "/mnt/c/Program Files/Wireshark/tshark.exe",
            "/mnt/d/Program Files/Wireshark/tshark.exe"
        ]
        for p in win_paths:
            if os.path.exists(p):
                return p, True
    return "tshark", False

def wsl_to_windows_path(path_str):
    if path_str.startswith("/mnt/"):
        parts = path_str.split("/")
        if len(parts) > 3:
            drive = parts[2].upper()
            rest = "\\".join(parts[3:])
            return f"{drive}:\\{rest}"
    return path_str

def is_readable_text(s, threshold=0.90):
    """
    Returns True if string 's' looks like readable text.
    Heuristic: 90% of chars must be printable, tab, or newline.
    """
    if not s: return False
    # Create a set of allowed characters (Alphanumeric + Punctuation + Whitespace)
    allowed = set(string.printable)
    readable_count = sum(1 for c in s if c in allowed)
    ratio = readable_count / len(s)
    return ratio > threshold

def build_command(tshark_bin, is_win_bin, network, interface, ssl_keys, sniff_mode):
    cmd = [tshark_bin, "-l", "-n"]
    
    if sniff_mode:
        cmd.extend([
            "-T", "fields",
            "-e", "frame.time",       
            "-e", "ip.src",           
            "-e", "ip.dst",           
            "-e", "_ws.col.Protocol", 
            "-e", "frame.len",        
            "-e", "_ws.col.Info",     
            "-e", "http2.data.data",  
            "-e", "http.file_data",   
            "-E", "separator=/t"      
        ])
        display_filter = "tcp || http2 || http"
    else:
        pass

    if interface:
        cmd.extend(["-i", interface])
    
    if ssl_keys:
        final_key_path = wsl_to_windows_path(ssl_keys) if is_win_bin else ssl_keys
        cmd.extend(["-o", f"tls.keylog_file:{final_key_path}"])

    is_ipv6 = isinstance(network, ipaddress.IPv6Network)
    proto = "ip6" if is_ipv6 else "ip"
    if network.prefixlen == 0:
         base_filter = f"{proto}"
    else:
        addr = network.network_address.compressed if is_ipv6 else network.network_address
        base_filter = f"{proto} host {addr}" if network.num_addresses == 1 else f"{proto} net {network.with_prefixlen}"
        
    cmd.extend(["-f", base_filter])
    if sniff_mode: cmd.extend(["-Y", display_filter])
    
    return cmd

def parse_args():
    p = argparse.ArgumentParser(description="Capture headers and clean text payloads.")
    p.add_argument("ip_range", help="IP range (0.0.0.0/0 for all)")
    p.add_argument("-i", "--interface", help="Interface name")
    p.add_argument("-o", "--outdir", default=".", help="Output directory")
    p.add_argument("-k", "--ssl-keys", help="Path to SSLKEYLOGFILE")
    p.add_argument("-t", "--timeout", type=int, help="Timeout in seconds")
    p.add_argument("--sniff", action="store_true", help="Enable payload decryption")
    return p.parse_args()

def main():
    args = parse_args()
    tshark_bin, is_win_bin = get_tshark_path()
    
    try:
        network = ipaddress.ip_network(args.ip_range, strict=False)
    except ValueError:
        sys.exit("Invalid CIDR")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / f"capture_{timestamp}.txt"

    cmd = build_command(tshark_bin, is_win_bin, network, args.interface, args.ssl_keys, args.sniff)
    
    print(f"Executing: {' '.join(cmd)}")
    print(f"Writing to: {outfile}")

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
                        if line:
                            if args.sniff:
                                parts = line.strip().split('\t')
                                if len(parts) >= 6:
                                    ts, src, dst, proto, length, info = parts[:6]
                                    
                                    data_hex = ""
                                    if len(parts) > 6 and parts[6]: data_hex = parts[6]
                                    if len(parts) > 7 and parts[7]: data_hex = parts[7]
                                    
                                    # 1. WRITE HEADER
                                    header_line = f"{ts} | {proto} | {src} -> {dst} | Len:{length} | {info}"
                                    f.write(header_line + "\n")
                                    print(header_line[:120])

                                    # 2. WRITE PAYLOAD (Strict Text Only)
                                    if data_hex:
                                        clean_hex = data_hex.replace(':', '')
                                        try:
                                            # STRICT DECODING: Fail immediately if not valid UTF-8
                                            decoded = binascii.unhexlify(clean_hex).decode('utf-8')
                                            
                                            # QUALITY CHECK: Skip if it looks like binary garbage
                                            if is_readable_text(decoded):
                                                body_out = f"    [PAYLOAD]:\n    {decoded}\n    {'-'*60}\n"
                                                f.write(body_out)
                                                if any(c in decoded for c in "{<"):
                                                    print(f"    [Clean Text]: {decoded[:80]}...")
                                            else:
                                                # Optional: Log that we skipped a binary blob
                                                # f.write("    [BINARY DATA SKIPPED]\n")
                                                pass
                                                
                                        except UnicodeDecodeError:
                                            # This is definitely binary (image/zip/etc)
                                            pass
                                        except Exception:
                                            pass
                            else:
                                f.write(line)
                    
                    if args.timeout and (datetime.datetime.now().timestamp() >= start_time + args.timeout):
                        print("\n[!] Timeout reached.")
                        proc.terminate()
                        break
            
            except KeyboardInterrupt:
                print("\nStopping capture...")
                proc.terminate()
                proc.wait()
                
    except Exception as e:
        sys.exit(f"Error: {e}")
    
    if outfile.stat().st_size == 0:
        print("\n[!] Output file is empty.")
    else:
        print(f"Capture complete. Log saved to: {outfile}")

if __name__ == "__main__":
    main()

