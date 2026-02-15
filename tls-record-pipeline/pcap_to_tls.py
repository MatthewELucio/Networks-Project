#!/usr/bin/env python3
"""
Batch TLS-record extraction from capture pcaps.

For each capture_*.pcap:
  - Extract TLS application-data records using tshark
  - Prepend LLM_IP headers from corresponding capture_*.txt
  - Write capture_*.tls.tsv

Requires:
  - tshark
  - capture_*.pcap
  - capture_*.txt
"""

import argparse
import subprocess
import sys
from pathlib import Path
import re

LLM_HEADER_RE = re.compile(r"^LLM_IP\s+\S+\s+\S+")


# -----------------------------
# Header extraction
# -----------------------------
def extract_llm_headers(capture_txt: Path):
    headers = []
    if not capture_txt.exists():
        return headers

    with capture_txt.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if LLM_HEADER_RE.match(line):
                headers.append(line)
            else:
                break
    return headers


# -----------------------------
# TLS extraction
# -----------------------------
def extract_tls_tsv(pcap: Path, out_tsv: Path):
    cmd = [
        "tshark",
        "-r", str(pcap),
        "-T", "fields",
        "-e", "frame.time_relative",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "tcp.stream",
        "-e", "tls.record.length",
        "-Y", "tls.record.content_type == 23",
        "-E", "separator=\t",
        "-E", "occurrence=f",
    ]

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"tshark failed on {pcap}:\n{proc.stderr}"
        )

    with out_tsv.open("a", encoding="utf-8") as f:
        f.write(proc.stdout)


# -----------------------------
# Main
# -----------------------------
def main():
    p = argparse.ArgumentParser(description="Batch TLS record extraction")
    p.add_argument("--input", required=True, help="Directory with capture_*.pcap")
    p.add_argument("--output", help="Output directory (default: same as input)")
    args = p.parse_args()

    in_dir = Path(args.input)
    out_dir = Path(args.output) if args.output else in_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    pcaps = sorted(in_dir.glob("capture_*.pcap"))
    if not pcaps:
        sys.exit("No capture_*.pcap files found")

    for pcap in pcaps:
        base = pcap.stem
        capture_txt = in_dir / f"{base}.txt"
        out_tsv = out_dir / f"{base}.tls.tsv"

        print(f"[+] Processing {pcap.name}")

        # Clear output file
        out_tsv.write_text("", encoding="utf-8")

        # 1️⃣ Copy LLM_IP headers
        headers = extract_llm_headers(capture_txt)
        if headers:
            with out_tsv.open("a", encoding="utf-8") as f:
                for h in headers:
                    f.write(h + "\n")
                f.write("\n")

        # 2️⃣ Append TLS records
        extract_tls_tsv(pcap, out_tsv)

        print(f"    → {out_tsv.name}")

    print("\nDone. TLS TSV files ready.")


if __name__ == "__main__":
    main()
