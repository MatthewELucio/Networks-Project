#!/usr/bin/env python3
"""
capture_chatgpt_network.py

Capture Wi-Fi (best-effort monitor/promiscuous) traffic for the network you're on,
include dynamic resolution of ChatGPT/OpenAI hostnames (to capture by IP),
and post-filter for TLS SNI / DNS queries containing "chatgpt" OR by resolved IPs.

Open AI usage:
  sudo python3 capture_chatgpt_network.py \
  --interface en0 \
  --duration 300 \
  --outfile ~/Desktop/openai_filtered.pcap

Anthropic usage:
    sudo python3 capture_chatgpt_network.py \
  --interface en0 \
  --provider anthropic \
  --duration 300 \
  --outfile ~/Desktop/anthropic_filtered.pcap


Notes:
 - Requires: tcpdump and tshark available in PATH.
 - Run with sudo so the script can capture and (optionally) toggle monitor mode.
 - Monitor mode handling is best-effort and differs by OS. The script attempts:
     - macOS: uses tcpdump -I (monitor mode) if supported
     - Linux: tries to use 'iw' to set interface to monitor mode (requires iw)
   If monitor mode cannot be enabled automatically, the script will continue but warn.
"""

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DEFAULT_HOSTS = [
    "chat.openai.com",
    "api.openai.com",
    "platform.openai.com",
    "openai.com",
    "cdn.openai.com",
]

PROVIDER_PROFILES = {
    "openai": {
        "hosts": [
            "chat.openai.com",
            "api.openai.com",
            "platform.openai.com",
            "openai.com",
            "cdn.openai.com",
        ],
        "keyword": "chatgpt",  # what to look for in SNI/DNS
    },
    "anthropic": {
        "hosts": [
            "api.anthropic.com",
        ],
        "keyword": "anthropic",
    },
}

def find_exe(names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None

def resolve_hostnames(hostnames, timeout=5.0):
    ipv4 = set()
    ipv6 = set()
    for h in hostnames:
        try:
            for res in socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP):
                fam = res[0]
                addr = res[4][0]
                if fam == socket.AF_INET:
                    ipv4.add(addr)
                elif fam == socket.AF_INET6:
                    ipv6.add(addr.split('%')[0])
        except Exception:
            # ignore unresolved names
            pass
    return sorted(ipv4), sorted(ipv6)

def build_bpf(base_bpf, ipv4_list, ipv6_list):
    parts = [base_bpf] if base_bpf else []
    for ip in ipv4_list:
        parts.append(f"host {ip}")
    for ip in ipv6_list:
        parts.append(f"ip6 host {ip}")
    return " or ".join(parts)

def build_tshark_ip_filter(ipv4_list, ipv6_list):
    parts = []
    for ip in ipv4_list:
        parts.append(f"ip.addr == {ip}")
    for ip in ipv6_list:
        parts.append(f"ipv6.addr == {ip}")
    if parts:
        return " or ".join(parts)
    return ""

def make_readable(path, invoking_user):
    try:
        if invoking_user and os.environ.get("SUDO_UID"):
            uid = int(os.environ["SUDO_UID"])
            gid = int(os.environ.get("SUDO_GID", uid))
            os.chown(path, uid, gid)
        os.chmod(path, 0o644)
    except Exception:
        pass

def enable_monitor_mode_linux(interface):
    """Try to set monitor mode on Linux using iw (best-effort). Returns True if changed."""
    iw = find_exe(["iw"])
    if not iw:
        return False, "iw not found"
    try:
        # bring interface down, set monitor, bring up
        subprocess.run(["ip", "link", "set", interface, "down"], check=False)
        subprocess.run(["iw", interface, "set", "monitor", "none"], check=False)
        subprocess.run(["ip", "link", "set", interface, "up"], check=False)
        return True, "monitor mode requested with iw (may require root and driver support)"
    except Exception as e:
        return False, str(e)

def try_tcpdump_monitor_supported(tcpdump_bin):
    """Return True if tcpdump accepts -I (monitor) option by probing --help output or version."""
    try:
        out = subprocess.run([tcpdump_bin, "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return "-I" in out.stdout or "monitor mode" in out.stdout
    except Exception:
        return False

def main():
    ap = argparse.ArgumentParser(description="Capture network traffic and filter for chatgpt (SNI/DNS or resolved IPs).")
    ap.add_argument("--interface", required=True, help="Capture interface (e.g., en0, wlan0)")
    ap.add_argument("--outfile", default="chatgpt_filtered.pcap", help="Final filtered pcap path")
    ap.add_argument("--raw", default=None, help="Raw capture path (intermediate). If omitted a temp file is used.")
    ap.add_argument("--duration", type=int, default=0, help="If >0 capture for this many seconds then stop.")
    ap.add_argument(
        "--provider",
        choices=["openai", "anthropic"],
        default=None,
        help="LLM provider profile (controls default hosts + keyword).",
    )
    ap.add_argument(
        "--keyword",
        default=None,
        help='Substring to match in TLS SNI / DNS (e.g. "chatgpt", "anthropic"). '
             "If omitted, uses the selected provider profile's default.",
    )
    ap.add_argument("--hosts", default=",".join(DEFAULT_HOSTS), help="Comma-separated hostnames to resolve for IP capture.")
    ap.add_argument("--bpf", default='tcp port 443 or udp port 53', help="Base BPF (default captures HTTPS + DNS).")
    args = ap.parse_args()

    tcpdump = find_exe(["tcpdump"])
    tshark = find_exe(["tshark"])
    if not tcpdump:
        print("[ERROR] tcpdump not found. Install tcpdump.", file=sys.stderr); sys.exit(2)
    if not tshark:
        print("[ERROR] tshark not found. Install tshark (Wireshark) and try again.", file=sys.stderr); sys.exit(2)

    invoking_user = os.environ.get("SUDO_USER") or os.environ.get("USER")

    raw_path = Path(args.raw).expanduser().resolve() if args.raw else Path(tempfile.NamedTemporaryFile(prefix="chatgpt_raw_", suffix=".pcap", delete=False).name)
    outfile_path = Path(args.outfile).expanduser().resolve()

    # hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]

    profile = PROVIDER_PROFILES[args.provider]

    # Hosts: CLI --hosts overrides profile; otherwise use profile hosts
    if args.hosts:
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    else:
        hosts = profile["hosts"]

    print(f"[i] Provider profile: {args.provider}")
    print(f"[i] Using hosts: {hosts}")
    ipv4_list, ipv6_list = resolve_hostnames(hosts)
    print(f"[i] Resolved IPv4: {ipv4_list}")
    print(f"[i] Resolved IPv6: {ipv6_list}")

    base_bpf = args.bpf
    bpf = build_bpf(base_bpf, ipv4_list, ipv6_list)
    print(f"[i] Final BPF for capture: {bpf}")

    # attempt to enable monitor mode (best-effort)
    monitor_arg = []
    platform = sys.platform
    monitor_enabled_msg = None
    if platform.startswith("darwin"):
        # macOS: try tcpdump -I for monitor mode
        if try_tcpdump_monitor_supported(tcpdump):
            monitor_arg = ["-I"]
            monitor_enabled_msg = "Using tcpdump -I (macOS monitor mode attempt)"
        else:
            monitor_enabled_msg = "tcpdump -I not supported; monitor mode not enabled automatically on macOS"
    elif platform.startswith("linux"):
        ok, msg = enable_monitor_mode_linux(args.interface)
        if ok:
            monitor_enabled_msg = f"Requested monitor mode on Linux (iw). {msg}"
        else:
            monitor_enabled_msg = f"Monitor mode could not be enabled automatically on Linux: {msg}"
    else:
        monitor_enabled_msg = "Unknown platform; monitor mode not attempted."

    print("[i] Monitor mode status:", monitor_enabled_msg)

    tcpdump_cmd = [tcpdump, "-n", "-s", "0", "-U", "-w", str(raw_path), "-i", args.interface] + monitor_arg + [bpf]
    print("[i] Running tcpdump:")
    print("    " + " ".join(map(str, tcpdump_cmd)))
    proc = None
    try:
        proc = subprocess.Popen(tcpdump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        start = time.time()
        if args.duration and args.duration > 0:
            while True:
                time.sleep(0.5)
                if proc.poll() is not None:
                    break
                if time.time() - start >= args.duration:
                    print(f"[i] Duration {args.duration}s reached — stopping capture.")
                    proc.send_signal(signal.SIGINT)
                    break
        else:
            try:
                while True:
                    time.sleep(0.5)
                    if proc.poll() is not None:
                        break
            except KeyboardInterrupt:
                print("\n[i] Ctrl-C received — stopping tcpdump...")
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)

        # wait for tcpdump exit
        try:
            outs, errs = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            outs, errs = ("","[tcpdump did not exit cleanly]")

        print(f"[+] Raw capture complete: {raw_path}")
        if invoking_user:
            make_readable(str(raw_path), invoking_user)

        # Build display filter:
        # 1) TLS SNI or DNS containing "chatgpt" or keyword
        keyword = args.keyword if args.keyword else profile["keyword"]
        sni_dns_filter = (
            f'tls.handshake.extensions_server_name contains "{keyword}" '
            f'or dns.qry.name contains "{keyword}"'
        )        
        
        # 2) OR IP address matches any resolved IPs
        ip_filter_part = build_tshark_ip_filter(ipv4_list, ipv6_list)
        if ip_filter_part:
            display_filter = f"({sni_dns_filter}) or ({ip_filter_part})"
        else:
            display_filter = sni_dns_filter

        print(f"[i] TShark display filter to run on raw pcap:\n    {display_filter}")

        tshark_cmd = [tshark, "-r", str(raw_path), "-Y", display_filter, "-w", str(outfile_path)]
        print("[i] Running tshark to create filtered pcap:")
        print("    " + " ".join(map(str, tshark_cmd)))
        res = subprocess.run(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            print("[!] tshark returned error. stderr:")
            print(res.stderr, file=sys.stderr)
            sys.exit(3)
        print(f"[+] Filtered pcap written: {outfile_path}")
        if invoking_user:
            make_readable(str(outfile_path), invoking_user)

        print("\nDone.")
        print(f"Raw capture:    {raw_path}")
        print(f"Filtered pcap:  {outfile_path}")
        if not args.raw:
            print("(Note: intermediate raw pcap created automatically. Delete it if you don't need it.)")

    except Exception as e:
        print(f"[!] Error while capturing: {e}", file=sys.stderr)
        if proc and proc.poll() is None:
            proc.kill()
    finally:
        pass

if __name__ == "__main__":
    main()
