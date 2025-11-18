import argparse
"""
ip_range_capture
================

Capture packets where either the source OR destination matches an IPv4/IPv6
CIDR range (optionally refined with an additional BPF filter), and write
human-readable tcpdump output to a timestamped text file.

Core Workflow:
1. Parse CLI arguments (CIDR, interface, output directory, timeout, snaplen, extra filter).
2. Validate / normalize the CIDR (strict=False allows host addresses without explicit /32 or /128).
3. Build an appropriate tcpdump command:
    - Uses 'host <addr>' if the network reduces to a single address.
    - Uses 'net <CIDR>' otherwise.
    - Note: tcpdump 'host' and 'net' match either src OR dst by default
      (effectively "src or dst host/net ...").
    - Adds an AND clause if --extra-filter is supplied.
4. Stream tcpdump stdout into a line-buffered UTF-8 text file whose name encodes
    the start timestamp and CIDR (slashes replaced by underscores).
5. Respect an optional timeout; otherwise run until interrupted (Ctrl+C).
6. Warn if not running as root (tcpdump may fail or show limited data).

Security / Permissions:
- tcpdump often requires root; script does not auto-escalate, it only prints a warning.
- User is responsible for having appropriate privileges and complying with local policy.

Files / Output:
- Output file pattern: capture_<YYYYmmdd_HHMMSS>_<CIDR_with_slash_replaced>.txt
- Stored in --outdir (created if missing).

Arguments:
- ip_range (positional): CIDR like 192.168.1.0/24 or 2001:db8::/64; host addresses accepted.
- -i / --interface: Network interface (e.g. eth0, en0). If omitted, tcpdump default selection applies.
- -o / --outdir: Directory for output file (default: current directory).
- -t / --timeout: Seconds to capture before graceful termination (default: indefinite).
- --snaplen: Snapshot length (tcpdump -s value); tradeoff between completeness and performance (default: 96).
- --extra-filter: Additional BPF expression ANDed with the base host/net filter (e.g. "tcp port 443").

Error Handling:
- Invalid CIDR -> exit code 2 with message to stderr.
- Missing tcpdump binary -> exit code 1 with message.
- KeyboardInterrupt -> terminates child process cleanly, then exits.

Function Overview:
- build_command(network, interface, snaplen, extra):
     Returns a list suitable for subprocess.Popen representing the tcpdump invocation.
- parse_args():
     Defines and parses CLI arguments.
- validate_network(ip_range):
     Returns an ipaddress network object; exits on failure.
- main():
     Orchestrates parsing, validation, command construction, timed streaming, and cleanup.

Extensibility Ideas:
- Add pcap output option alongside text.
- Support JSON structuring via tshark for downstream automation.
- Implement graceful SIGTERM handling (multiprocessing / signal module).
- Allow rotation for long captures (size- or time-based).

Notes:
- Uses line-buffered writes for near-real-time file visibility.
- Defaults (-nn -v -U) favor raw numeric addresses/ports, verbose decoding, and packet-by-packet flush.
- Filtering is symmetric: matches when src OR dst is within the provided host/network.
"""
# Example run:
# python ip_range_capture.py 192.168.1.0/24 -i eth0 -t 60 --extra-filter "tcp port 443"
import datetime
import ipaddress
import os
import subprocess
import sys
from pathlib import Path

#!/usr/bin/env python3

def build_command(network: ipaddress._BaseNetwork, interface: str | None, snaplen: int, extra: str | None):
    # Use 'host' if single-address network, else 'net'
    if network.num_addresses == 1:
        base_filter = f"host {network.network_address}"
    else:
        base_filter = f"net {network.with_prefixlen}"
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
    safe_name = str(network.with_prefixlen).replace("/", "_")
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
    except FileNotFoundError:
        print("tcpdump not found. Install tcpdump first.", file=sys.stderr)
        sys.exit(1)
    print("Capture complete.")

if __name__ == "__main__":
    main()