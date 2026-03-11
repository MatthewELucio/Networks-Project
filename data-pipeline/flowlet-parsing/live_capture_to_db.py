import argparse
import datetime
import ipaddress
import os
import subprocess
import sys
import select
import platform
import json
from pathlib import Path
from collections import defaultdict
import statistics
from typing import Optional, Union

# Cloud DB: set True to use Firebase by default; overridden by --cloud-db / --no-cloud-db.
USE_CLOUD_DB = True

try:
    import database as _db_local
except ImportError:
    _db_local = None
try:
    import database_firebase as _db_cloud
except ImportError:
    _db_cloud = None

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

def build_command(tshark_bin, is_win_bin, network, interface, ssl_keys):
    cmd = [tshark_bin, "-l", "-n"]
    cmd.extend([
        "-T", "fields",
        # MUST MATCH BATCH SCRIPT ORDER EXACTLY
        "-e", "frame.time_epoch", "-e", "ip.dsfield", "-e", "ip.ttl", 
        "-e", "ip.id", "-e", "ip.flags", "-e", "ip.proto", "-e", "ip.len", # 0-6
        "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport", # 7-10
        "-e", "tcp.flags.str", "-e", "tcp.checksum", "-e", "tcp.seq", # 11-13
        "-e", "tcp.ack", "-e", "tcp.window_size_value", "-e", "tcp.len", # 14-16
        "-e", "tls.handshake.extensions_server_name", # 17
        "-e", "http2.headers.authority", # 18
        "-e", "dns.qry.name", # 19
        "-E", "separator=/t", "-E", "occurrence=f"
    ])
    if interface: cmd.extend(["-i", interface])
    if ssl_keys:
        cmd.extend(["-o", f"tls.keylog_file:{ssl_keys}"])

    is_ipv6 = isinstance(network, ipaddress.IPv6Network)
    proto = "ip6" if is_ipv6 else "ip"
    addr = network.network_address.compressed if is_ipv6 else network.network_address
    base_filter = f"{proto} host {addr}" if network.num_addresses == 1 else f"{proto} net {network.with_prefixlen}"
    cmd.extend(["-f", base_filter])
    return cmd

class LiveFlowletManager:
    """Works with either SQLite session (capture_id int) or Firebase session (capture_id str)."""
    def __init__(self, db_session, capture_id: Union[int, str], flowlet_cls, threshold=0.1):
        self.db = db_session
        self.capture_id = capture_id
        self.flowlet_cls = flowlet_cls
        self.threshold = threshold
        self.flows = defaultdict(list)
        self.llm_ip_map = {}
        self.flowlet_counts = defaultdict(int)

    def process_packet(self, pkt):
        # detection logic using pkt['names'] populated from indices 17, 18, 19
        detected_name = None
        for kw in TARGET_KEYWORDS:
            if kw in pkt['names']:
                detected_name = kw.upper()
                break

        if detected_name:
            # Check the remote IP (non-private) to map the LLM server
            # We check dst (request) and src (response) like the batch script
            if pkt['dst'] not in self.llm_ip_map and not ipaddress.ip_address(pkt['dst']).is_private:
                self.llm_ip_map[pkt['dst']] = detected_name
                print(f"🔥 [DETECTION] {detected_name} mapped to {pkt['dst']}")
            elif pkt['src'] not in self.llm_ip_map and not ipaddress.ip_address(pkt['src']).is_private:
                self.llm_ip_map[pkt['src']] = detected_name
                print(f"🔥 [DETECTION] {detected_name} mapped to {pkt['src']}")

        # Group packets into flows (Bidirectional)
        a = f"{pkt['src']}:{pkt['sport']}"
        b = f"{pkt['dst']}:{pkt['dport']}"
        flow_key = tuple(sorted([a, b]) + [pkt['proto']])
        
        if self.flows[flow_key]:
            last_ts = self.flows[flow_key][-1]['ts']
            if (pkt['ts'] - last_ts) > self.threshold:
                self.flush_flowlet(flow_key)

        self.flows[flow_key].append(pkt)

    def flush_flowlet(self, flow_key):
        pkts = self.flows[flow_key]
        if not pkts: return

        self.flowlet_counts[flow_key] += 1
        src_ip, dst_ip = pkts[0]['src'], pkts[0]['dst']
        llm_name = self.llm_ip_map.get(src_ip) or self.llm_ip_map.get(dst_ip)
        
        # --- NEW: Advanced Statistics ---
        sorted_pkts = sorted(pkts, key=lambda p: p['ts'])
        inter_packet_times = [
            sorted_pkts[i]['ts'] - sorted_pkts[i-1]['ts'] for i in range(1, len(sorted_pkts))
        ]
        packet_sizes = [p['len'] for p in sorted_pkts]

        ipt_mean = statistics.mean(inter_packet_times) if inter_packet_times else 0.0
        ipt_std = statistics.stdev(inter_packet_times) if len(inter_packet_times) > 1 else 0.0
        ps_mean = statistics.mean(packet_sizes) if packet_sizes else 0.0
        ps_std = statistics.stdev(packet_sizes) if len(packet_sizes) > 1 else 0.0

        # --- NEW: Direction Encoding ---
        outgoing = None
        direction_encoded = 0
        if llm_name:
            if dst_ip in self.llm_ip_map:
                outgoing = True
                direction_encoded = 1
            elif src_ip in self.llm_ip_map:
                outgoing = False
                direction_encoded = -1

        start_ts, end_ts = sorted_pkts[0]['ts'], sorted_pkts[-1]['ts']
        total_bytes = sum(packet_sizes)
        
        # --- SAVE TO DB (Matches full feature set) ---
        new_flowlet = self.flowlet_cls(
            capture_id=self.capture_id,
            src_ip=src_ip, src_port=pkts[0]['sport'],
            dst_ip=dst_ip, dst_port=pkts[0]['dport'],
            protocol=pkts[0]['proto'],
            flowlet_id=self.flowlet_counts[flow_key],
            traffic_class="llm" if llm_name else "non_llm",
            llm_name=llm_name,
            outgoing=outgoing,
            direction_encoded=direction_encoded,
            start_ts=start_ts, end_ts=end_ts,
            duration=end_ts - start_ts,
            packet_count=len(pkts),
            total_bytes=total_bytes,
            inter_packet_time_mean=ipt_mean,
            inter_packet_time_std=ipt_std,
            packet_size_mean=ps_mean,
            packet_size_std=ps_std,
            # Store raw sequences as JSON strings for Markov modeling
            inter_packet_times=json.dumps(inter_packet_times),
            packet_sizes=json.dumps(packet_sizes)
        )
        self.db.add(new_flowlet)
        self.db.commit()
        self.flows[flow_key] = []

def main():
    p = argparse.ArgumentParser(description="Live packet sniffer and flowlet parser.")
    p.add_argument("ip_range", help="CIDR range to sniff")
    p.add_argument("-i", "--interface", help="Network interface")
    p.add_argument("-k", "--ssl-keys", help="Path to SSLKEYLOGFILE")
    p.add_argument("--db-path", default="data/networks_project.db", help="SQLite path (ignored when using Firebase).")
    p.add_argument("--capture-id", help="Resume: Capture ID (int for SQLite, doc ID string for Firebase). Omit to create new.")
    p.add_argument("--cloud-db", action="store_true", default=None, help="Use Firebase Cloud Firestore.")
    p.add_argument("--no-cloud-db", action="store_true", dest="no_cloud_db", help="Use local SQLite (default).")
    p.add_argument("-t", "--timeout", type=int, help="Timeout in seconds")
    args = p.parse_args()

    use_cloud_db = False if args.no_cloud_db else (args.cloud_db if args.cloud_db is not None else USE_CLOUD_DB)
    if use_cloud_db and _db_cloud is None:
        sys.exit("❌ Error: --cloud-db requested but database_firebase not available.")
    if not use_cloud_db and _db_local is None:
        sys.exit("❌ Error: database.py not found. Ensure it is in the same directory.")
    mod = _db_cloud if use_cloud_db else _db_local
    init_database = mod.init_database
    get_db_session = mod.get_db_session
    Capture = mod.Capture
    Flowlet = mod.Flowlet

    tshark_bin, is_win_bin = get_tshark_path()
    try:
        network = ipaddress.ip_network(args.ip_range, strict=False)
    except ValueError:
        sys.exit(f"❌ Error: {args.ip_range} is not a valid IP range.")

    init_database(args.db_path)
    db = get_db_session()

    # --- LOGIC FOR INDEPENDENT RUNS ---
    if args.capture_id:
        # Resume existing capture: int for SQLite, string for Firebase (doc ID)
        capture_id_arg = int(args.capture_id) if not use_cloud_db else args.capture_id
        capture = db.query(Capture).get(capture_id_arg)
        if not capture:
            sys.exit(f"❌ Error: Capture ID {args.capture_id} not found.")
        capture_id = capture.id if not use_cloud_db else (capture.id or capture.file_path)
    else:
        # Create new record
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_name = f"MANUAL_LIVE_{args.interface or 'default'}_{timestamp}"
        capture = Capture(
            file_path=unique_name,
            status="active",
            notes=f"Manual Run on {args.ip_range}",
        )
        db.add(capture)
        db.commit()
        if not use_cloud_db:
            db.refresh(capture)
        capture_id = capture.id
        print(f"📝 Created new manual capture record (ID: {capture_id})")

    manager = LiveFlowletManager(db, capture_id, Flowlet)
    
    cmd = build_command(tshark_bin, is_win_bin, network, args.interface, args.ssl_keys)

    print(f"🚀 Starting Live Pipeline for ID {capture_id}...")
    start_time = datetime.datetime.now().timestamp()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    try:
        while True:
            # Check Timeout
            if args.timeout and (datetime.datetime.now().timestamp() - start_time) > args.timeout:
                print(f"⏰ Timeout of {args.timeout}s reached. Shutting down...")
                break

            # Non-blocking read check
            r, _, _ = select.select([proc.stdout], [], [], 1.0)
            if r:
                line = proc.stdout.readline()
                if not line: break
                
                parts = line.strip().split('\t')
                # Pad to 20 columns to match your batch logic and avoid IndexErrors
                parts += [""] * (20 - len(parts)) 

                try:
                    # 1. Map fields exactly like the batch script
                    epoch = parts[0]
                    src = parts[7]
                    sport = parts[8]
                    dst = parts[9]
                    dport = parts[10]
                    proto = parts[5]
                    ip_len = int(parts[6] or 0)
                    
                    # 2. Detection (Matches your exact batch logic)
                    # Combine SNI, HTTP2 Authority, and DNS Query Name
                    names = (parts[17] + parts[18] + parts[19]).lower()
                    
                    pkt = {
                        'ts': float(epoch),
                        'src': src, 'sport': sport,
                        'dst': dst, 'dport': dport,
                        'proto': proto, 'len': ip_len,
                        'names': names
                    }
                    manager.process_packet(pkt)
                except (ValueError, IndexError):
                    continue
            
    except KeyboardInterrupt:
        print("\n🛑 Stopped by user. Flushing flows...")
    finally:
        for key in list(manager.flows.keys()):
            manager.flush_flowlet(key)
            
        try:
            final_db = get_db_session()
            final_capture = final_db.query(Capture).get(capture_id)
            if final_capture:
                # --- ADD THIS LINE ---
                # This saves the mapping so the frontend knows which IPs belong to which LLM
                final_capture.llm_ip_map = json.dumps(manager.llm_ip_map)
                
                final_capture.status = "completed"
                final_db.commit()
                print(f"✅ Saved LLM IP Map: {manager.llm_ip_map}")
            final_db.close()
        except Exception as e:
            print(f"⚠️ Status/Map update failed: {e}")
            
        proc.terminate()
        print(f"✅ Capture {capture_id} finished.")

if __name__ == "__main__":
    main()