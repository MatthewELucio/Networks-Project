#!/usr/bin/env python3
"""
Script to convert a .pcap file to a .txt file in the same style as ip_range_capture.py captures.
Usage: python pcap_to_txt.py -i input.pcap -o output.txt
"""
import argparse
import subprocess
import sys
from pathlib import Path
import threading
import queue
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None
import threading
import queue

def parse_args():
    p = argparse.ArgumentParser(description="Convert .pcap to .txt in tcpdump text style.")
    p.add_argument("-i", "--input", required=True, help="Input .pcap file")
    p.add_argument("-o", "--output", required=True, help="Output .txt file")
    p.add_argument("--snaplen", type=int, default=96, help="Snapshot length in bytes (default: 96)")
    p.add_argument('--start', type=str, default=None, help='Start time/date (format: YYYY-MM-DD HH:MM:SS)')
    p.add_argument('--end', type=str, default=None, help='End time/date (format: YYYY-MM-DD HH:MM:SS)')
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
    # Note: tcpdump does not support direct time range filtering, so we filter output lines by timestamp
    start_time = args.start
    end_time = args.end
    print(f"Running: {' '.join(cmd)}")
    q = queue.Queue(maxsize=10000)
    stop_token = object()

    def writer_thread():
        with output_txt.open("w", buffering=1, encoding="utf-8") as f:
            while True:
                item = q.get()
                if item is stop_token:
                    break
                f.write(item)
                q.task_done()

    t = threading.Thread(target=writer_thread)
    t.start()
    import re, datetime
    line_count = 0
    import os
    show_progress = sys.stdout.isatty() and tqdm is not None
    if show_progress:
        pbar = tqdm(desc="Processing lines", unit="lines")
    else:
        pbar = None
        if tqdm is None:
            print("[INFO] tqdm not installed: progress bar will not be shown.")
    try:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                if start_time or end_time:
                    m = re.match(r'^(\d{2}:\d{2}:\d{2}(?:\.\d+)?)', line)
                    if m:
                        line_time = m.group(1)
                        base_date = "1970-01-01"
                        if start_time and len(start_time.split()) > 1:
                            base_date = start_time.split()[0]
                        try:
                            line_dt = datetime.datetime.strptime(f"{base_date} {line_time}", "%Y-%m-%d %H:%M:%S.%f")
                        except ValueError:
                            try:
                                line_dt = datetime.datetime.strptime(f"{base_date} {line_time}", "%Y-%m-%d %H:%M:%S")
                            except Exception:
                                q.put(line)
                                if pbar is not None:
                                    pbar.update(1)
                                continue
                        if start_time:
                            start_dt = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                            if line_dt < start_dt:
                                if pbar is not None:
                                    pbar.update(1)
                                continue
                        if end_time:
                            end_dt = datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
                            if line_dt > end_dt:
                                if pbar is not None:
                                    pbar.update(1)
                                continue
                        q.put(line)
                    else:
                        q.put(line)
                else:
                    q.put(line)
                if pbar is not None:
                    pbar.update(1)
            proc.wait()
            q.put(stop_token)
            t.join()
        finally:
            if pbar is not None:
                pbar.close()
    except FileNotFoundError as exc:
        if exc.filename == cmd[0]:
            print("tcpdump not found. Install tcpdump first.", file=sys.stderr)
        else:
            print(f"Failed to create output file {output_txt}: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"Wrote output to {output_txt}")

if __name__ == "__main__":
    main()
