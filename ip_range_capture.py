import argparse

# Script to capture TCP/IP packets based on a specified IP or IP range, ChatGPT 5.0 generated.
# Requires tcpdump installed, usually needs root privileges (sudo before python invocation)

# Example run:
# python ip_range_capture.py 192.168.1.0/24 -i eth0 -t 60 --extra-filter "tcp port 443"

# Typical run:
# sudo python ip_range_capture.py <IP ADDRESS PULLED FROM WIRESHARK>
# <RENAME FILE AND MOVE TO PROPER LOCATION AFTER>

import datetime
import ipaddress
import os
import subprocess
import sys
from pathlib import Path

#!/usr/bin/env python3

def build_command(network: ipaddress._BaseNetwork, interface: str | None, snaplen: int, extra: str | None):
    is_ipv6 = isinstance(network, ipaddress.IPv6Network)
    proto = "ip6" if is_ipv6 else "ip"
    # Use 'host' if single-address network, else 'net'
    if network.num_addresses == 1:
        base_filter = f"{proto} host {network.network_address.compressed if is_ipv6 else network.network_address}"
    else:
        base_filter = f"{proto} net {network.with_prefixlen}"
    if extra:
        base_filter = f"({base_filter}) and ({extra})"
    cmd = ["tcpdump", "-nn", "-v", "-U", "-s", str(snaplen), base_filter]
    if interface:
        cmd.insert(1, "-i")
        cmd.insert(2, interface)
    return cmd

def parse_args():
    p = argparse.ArgumentParser(description="Capture TCP/IP packets filtered by an IP (CIDR) range.")
    p.add_argument("ip_range", help="IP range in CIDR form (e.g. 192.168.1.0/24 or 2001:db8::/64)")
    p.add_argument("-i", "--interface", help="Network interface (default: system default)")
    p.add_argument("-o", "--outdir", default=".", help="Directory to store capture text file")
    p.add_argument("-t", "--timeout", type=int, help="Seconds to run before stopping (default: until Ctrl+C)")
    p.add_argument("--snaplen", type=int, default=96, help="Snapshot length in bytes (default: 96)")
    p.add_argument("--extra-filter", help="Additional tcpdump filter (BPF syntax) to AND with IP range")
    return p.parse_args()

def validate_network(ip_range: str):
    try:
        return ipaddress.ip_network(ip_range, strict=False)
    except ValueError as e:
        print(f"Invalid CIDR/network: {e}", file=sys.stderr)
        sys.exit(2)

def main():
    args = parse_args()
    if os.geteuid() != 0:
        print("Warning: tcpdump typically requires root privileges.", file=sys.stderr)
    network = validate_network(args.ip_range)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = str(network.with_prefixlen).replace("/", "_").replace(":", "-")
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / f"capture_{timestamp}_{safe_name}.txt"
    cmd = build_command(network, args.interface, args.snaplen, args.extra_filter)
    print(f"Executing: {' '.join(cmd)}")
    print(f"Writing to: {outfile}")
    try:
        with outfile.open("w", buffering=1, encoding="utf-8") as f:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                if args.timeout:
                    end_time = datetime.datetime.now().timestamp() + args.timeout
                    while proc.poll() is None:
                        line = proc.stdout.readline()
                        if line:
                            f.write(line)
                        if datetime.datetime.now().timestamp() >= end_time:
                            proc.terminate()
                            break
                else:
                    for line in proc.stdout:
                        f.write(line)
            except KeyboardInterrupt:
                print("Stopping capture...")
                proc.terminate()
            proc.wait()
    except FileNotFoundError as exc:
        if exc.filename == cmd[0]:
            print("tcpdump not found. Install tcpdump first.", file=sys.stderr)
        else:
            print(f"Failed to create output file {outfile}: {exc}", file=sys.stderr)
        sys.exit(1)
    print("Capture complete.")

if __name__ == "__main__":
    main()