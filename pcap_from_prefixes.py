#!/usr/bin/env python3
import json
import subprocess
import argparse
import shlex

def build_bpf_filter(prefixes):
    """
    Given a list of prefixes like '20.0.53.96/28', returns a tcpdump/tshark
    BPF filter string like '(net 20.0.53.96/28 or net 52.255.111.32/28 ...)'.
    """
    parts = []
    for p in prefixes:
        parts.append(f"net {p}")
    return " or ".join(parts)


def main():
    parser = argparse.ArgumentParser(
        description="Perform a packet capture filtered by prefixes in a JSON file."
    )
    parser.add_argument("json_file", help="Path to JSON file with prefixes")
    parser.add_argument(
        "-o", "--output", default="capture.pcap",
        help="Output pcap file name (default: capture.pcap)"
    )
    parser.add_argument(
        "-i", "--interface", default="any",
        help="Network interface to capture on (default: any)"
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Optional packet limit (e.g. --limit 100)"
    )
    parser.add_argument(
        "--tool", choices=["tcpdump", "tshark"], default="tcpdump",
        help="Capture tool to use (default: tcpdump)"
    )
    args = parser.parse_args()

    # Load JSON file
    with open(args.json_file, "r") as f:
        data = json.load(f)

    prefixes = [p["ipv4Prefix"] for p in data.get("prefixes", [])]
    if not prefixes:
        print("No prefixes found in the JSON file.")
        return

    bpf_filter = build_bpf_filter(prefixes)
    print(f"[*] Using filter:\n{bpf_filter}\n")

    if args.tool == "tcpdump":
        cmd = f"sudo tcpdump -i {args.interface} -w {args.output} {shlex.quote(bpf_filter)}"
        if args.limit > 0:
            cmd += f" -c {args.limit}"
    else:
        cmd = f"sudo tshark -i {args.interface} -w {args.output} -f {shlex.quote(bpf_filter)}"
        if args.limit > 0:
            cmd += f" -c {args.limit}"

    print(f"[*] Running: {cmd}")
    subprocess.run(cmd, shell=True)


if __name__ == "__main__":
    main()
