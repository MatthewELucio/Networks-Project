#!/usr/bin/env python3
"""
Parse TLS record TSV (from tshark) into record dicts.
"""

from pathlib import Path
from typing import List, Dict, Any

import re

LLM_HEADER_RE = re.compile(r"^LLM_IP\s+(?P<llm>\S+)\s+(?P<ip>\S+)$")

def parse_llm_header(lines):
    """
    Parse leading LLM_IP lines.
    Returns (llm_ip_map, start_idx).
    """
    llm_ip_map = {}
    idx = 0
    while idx < len(lines):
        line = lines[idx].strip()
        if not line:
            idx += 1
            continue
        m = LLM_HEADER_RE.match(line)
        if not m:
            break
        llm_ip_map[m.group("ip")] = m.group("llm")
        idx += 1
    return llm_ip_map, idx



def parse_tls_records_with_headers(path: Path):
    with path.open("r", encoding="utf-8") as f:
        lines = [l.rstrip("\n") for l in f]

    llm_ip_map, start_idx = parse_llm_header(lines)

    records = []
    for line_no, line in enumerate(lines[start_idx:], start=start_idx + 1):
        if not line or line.startswith("#"):
            continue

        parts = line.split("\t")
        if len(parts) < 7:
            raise ValueError(
                f"{path}:{line_no} — expected 7 columns, got {len(parts)}"
            )

        ts, src, sport, dst, dport, stream, tls_len = parts[:7]

        records.append({
            "ts": float(ts),
            "src_ip": src,
            "src_port": int(sport),
            "dst_ip": dst,
            "dst_port": int(dport),
            "stream": int(stream),
            "length": int(tls_len),
            "proto": "TLS",
        })

    return records, llm_ip_map
