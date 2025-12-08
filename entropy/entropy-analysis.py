#!/usr/bin/env python3
"""
pcap_byte_value_visualizer.py

Zoom-style visualization: plot raw byte values across packets and offsets.

Generates:
  - byte_matrix.png : heatmap where X=byte offset, Y=packet index, color=byte value (0–255)
  - bit_matrix.png  : optional bit-level heatmap (X=bit offset, Y=packet index, color=0/1)

Dependencies:
  pip install scapy numpy matplotlib
"""

import argparse
import numpy as np
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, TCP, UDP, Raw


def parse_args():
    p = argparse.ArgumentParser(
        description="Visualize byte values across packets/offsets from a PCAP."
    )
    p.add_argument("pcap", help="Path to pcap file")

    # Basic filters so you can isolate your application traffic
    p.add_argument("--src-ip", help="Filter: source IP", default=None)
    p.add_argument("--dst-ip", help="Filter: destination IP", default=None)
    p.add_argument("--src-port", type=int, help="Filter: source port", default=None)
    p.add_argument("--dst-port", type=int, help="Filter: destination port", default=None)
    p.add_argument(
        "--protocol",
        choices=["tcp", "udp", "any"],
        default="any",
        help="Transport protocol filter (default: any)",
    )
    p.add_argument(
        "--min-len",
        type=int,
        default=1,
        help="Minimum payload length to include (default: 1 byte)",
    )
    p.add_argument(
        "--max-packets",
        type=int,
        default=0,
        help="Max packets to process (0 = no limit)",
    )
    p.add_argument(
        "--no-bit-matrix",
        action="store_true",
        help="Skip generating bit_matrix.png",
    )
    return p.parse_args()


def match_filters(pkt, args):
    if IP not in pkt:
        return False

    ip = pkt[IP]

    if args.src_ip and ip.src != args.src_ip:
        return False
    if args.dst_ip and ip.dst != args.dst_ip:
        return False

    layer = None
    if args.protocol in ("tcp", "any") and TCP in pkt:
        layer = pkt[TCP]
    elif args.protocol in ("udp", "any") and UDP in pkt:
        layer = pkt[UDP]
    else:
        return False

    if args.src_port and layer.sport != args.src_port:
        return False
    if args.dst_port and layer.dport != args.dst_port:
        return False

    if Raw not in pkt:
        return False

    payload = bytes(pkt[Raw].load)
    if len(payload) < args.min_len:
        return False

    return True


def make_byte_matrix(payloads, pad_value=np.nan):
    """
    payloads: list of bytes objects
    Returns: 2D numpy array (num_packets, max_len) with byte values or pad_value.
    """
    num_packets = len(payloads)
    max_len = max(len(p) for p in payloads)

    # Use float so we can store NaN for padding; real bytes are 0–255.
    mat = np.full((num_packets, max_len), pad_value, dtype=float)

    for i, p in enumerate(payloads):
        L = len(p)
        mat[i, :L] = np.frombuffer(p, dtype=np.uint8)

    return mat


def make_bit_matrix(payloads, pad_value=np.nan):
    """
    payloads: list of bytes objects
    Returns: 2D numpy array (num_packets, max_bits) with bit values 0/1 or pad_value.
    Bits are ordered per packet: byte0[7..0], byte1[7..0], ...
    """
    num_packets = len(payloads)
    max_len = max(len(p) for p in payloads)
    max_bits = max_len * 8

    mat = np.full((num_packets, max_bits), pad_value, dtype=float)

    for i, p in enumerate(payloads):
        bytes_arr = np.frombuffer(p, dtype=np.uint8)
        bit_list = []
        for b in bytes_arr:
            # bits from MSB to LSB
            for bit_pos in range(7, -1, -1):
                bit_list.append((b >> bit_pos) & 1)
        bits = np.array(bit_list, dtype=float)
        mat[i, :len(bits)] = bits

    return mat


def main():
    args = parse_args()

    print(f"[+] Loading PCAP: {args.pcap}")
    pkts = rdpcap(args.pcap)
    print(f"[+] Total packets in PCAP: {len(pkts)}")

    payloads = []

    for pkt in pkts:
        if args.max_packets and len(payloads) >= args.max_packets:
            break
        try:
            if match_filters(pkt, args):
                payloads.append(bytes(pkt[Raw].load))
        except Exception:
            # Skip malformed/weird packets
            continue

    print(f"[+] Packets matching filters with payloads: {len(payloads)}")

    if not payloads:
        print("[!] No payloads matched the given filters. Nothing to visualize.")
        return

    # ----- BYTE MATRIX -----
    byte_mat = make_byte_matrix(payloads)
    num_packets, max_len = byte_mat.shape
    print(f"[+] Byte matrix shape: {byte_mat.shape} (packets x byte offsets)")

    # For plotting, mask NaNs so they don't affect color scale
    masked_bytes = np.ma.masked_invalid(byte_mat)

    print("[+] Saving byte_matrix.png")
    plt.figure(figsize=(10, 6))
    im = plt.imshow(
        masked_bytes,
        aspect="auto",
        interpolation="nearest",
        origin="lower",
    )
    cbar = plt.colorbar(im)
    cbar.set_label("Byte Value (0–255)")
    plt.title("Byte Values Across Packets and Offsets")
    plt.xlabel("Byte Offset")
    plt.ylabel("Packet Index")
    plt.tight_layout()
    plt.savefig("byte_matrix.png", dpi=200)
    plt.close()

    # ----- BIT MATRIX (optional) -----
    if not args.no_bit_matrix:
        print("[+] Building bit matrix (this can be large for long payloads)...")
        bit_mat = make_bit_matrix(payloads)
        num_packets_b, max_bits = bit_mat.shape
        print(f"[+] Bit matrix shape: {bit_mat.shape} (packets x bit offsets)")

        masked_bits = np.ma.masked_invalid(bit_mat)

        print("[+] Saving bit_matrix.png")
        plt.figure(figsize=(10, 6))
        im2 = plt.imshow(
            masked_bits,
            aspect="auto",
            interpolation="nearest",
            origin="lower",
        )
        cbar2 = plt.colorbar(im2)
        cbar2.set_label("Bit Value (0 or 1)")
        plt.title("Bit Values Across Packets and Bit Offsets")
        plt.xlabel("Bit Offset")
        plt.ylabel("Packet Index")
        plt.tight_layout()
        plt.savefig("bit_matrix.png", dpi=200)
        plt.close()
    else:
        print("[+] Skipping bit_matrix.png (flag --no-bit-matrix was set)")

    print("[+] Done.")
    print("    Generated: byte_matrix.png" + ("" if args.no_bit_matrix else ", bit_matrix.png"))


if __name__ == "__main__":
    main()
