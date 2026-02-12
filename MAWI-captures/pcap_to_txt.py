#!/usr/bin/env python3
"""
Script to convert a .pcap file to a .txt file in the same style as ip_range_capture.py captures.
Usage: python pcap_to_txt.py -i input.pcap -o output.txt
"""
import argparse
import subprocess
import sys
from pathlib import Path

def parse_args():
    p = argparse.ArgumentParser(description="Convert .pcap to .txt in tcpdump text style.")
    p.add_argument("-i", "--input", required=True, help="Input .pcap file")
    p.add_argument("-o", "--output", required=True, help="Output .txt file")
    p.add_argument("--snaplen", type=int, default=96, help="Snapshot length in bytes (default: 96)")
    return p.parse_args()

def main():
    args = parse_args()
    input_pcap = Path(args.input)
    output_txt = Path(args.output)
    if not input_pcap.exists():
        print(f"Input file {input_pcap} does not exist.", file=sys.stderr)
        sys.exit(1)
    cmd = [
        "tcpdump", "-nn", "-v", "-s", str(args.snaplen), "-r", str(input_pcap)
    ]
    print(f"Running: {' '.join(cmd)}")
    try:
        with output_txt.open("w", buffering=1, encoding="utf-8") as f:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                f.write(line)
            proc.wait()
    except FileNotFoundError as exc:
        if exc.filename == cmd[0]:
            print("tcpdump not found. Install tcpdump first.", file=sys.stderr)
        else:
            print(f"Failed to create output file {output_txt}: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"Wrote output to {output_txt}")

if __name__ == "__main__":
    main()
