

# Traffic Capture and Flowlet Analysis Pipeline

This project analyzes encrypted LLM traffic using both packet-level and TLS-record–level flowlets.
All analysis stages share the same capture and ground-truth labeling to ensure consistency.

---

## Pipeline Overview

The pipeline consists of four stages:

1. **Traffic Capture & Ground Truth Labeling**
2. **Derived TLS Record Extraction (optional)**
3. **Flowlet Construction**
4. **Feature Extraction for Analysis / ML**

Each stage consumes the output of the previous stage.

---

## 1. Traffic Capture & Ground Truth Labeling

Live traffic is captured using a custom `tshark`-based script.

**Output files:**
- `capture_<timestamp>.pcap` – raw packet capture
- `capture_<timestamp>.txt` – tcpdump-style text capture with ground truth headers

The text capture begins with explicit LLM endpoint declarations:


These headers provide deterministic ground truth for all downstream analysis.

---

## 2. TLS Record Extraction (Derived Input)

TLS application-data records are extracted from the pcap using `tshark`.

This step is **optional** and only required for TLS-based flowlet analysis.

**Script:**
- `extract_tls_records_batch.py`

**Input:**
- `capture_*.pcap`
- `capture_*.txt` (for LLM_IP headers)

**Output:**
- `capture_*.tls.tsv`

Each `.tls.tsv` file preserves the original `LLM_IP` headers and contains
tab-separated TLS application records.

---

## 3. Flowlet Construction

Two flowlet parsers are provided:

### Packet-Based Flowlets
**Script:**
- `parse_flowlets_simple.py`

**Input:**
- `capture_*.txt`

Packets are grouped into flows and split into flowlets using inter-packet gaps.

---

### TLS-Based Flowlets
**Script:**
- `parse_flowlets_tls.py`

**Input:**
- `capture_*.tls.tsv`

TLS application records are grouped by TCP stream and split into flowlets
using inter-record time gaps.

---

## 4. Feature Extraction & Output

Both flowlet parsers produce feature-compatible JSON output:

- `flowlets_packets.json`
- `flowlets_tls.json`

Each flowlet includes:
- Timing features
- Size statistics
- Direction labeling
- Traffic class (`llm` / `non_llm`)
- Source file reference

Ground truth is inherited exclusively from `LLM_IP` headers.

---

## Script Flow Summary


Live Traffic
     ↓
Capture Script
     ↓
capture_*.pcap + capture_*.txt
     ↓
┌───────────────────────────┬───────────────────────────┐
│ Packet-Level Analysis     │ TLS Record-Level Analysis  │
│                           │                           │
│ parse_flowlets_simple.py  │ extract_tls_records_batch │
│                           │           ↓               │
│                           │ parse_flowlets_tls.py     │
└───────────────────────────┴───────────────────────────┘

Models



“Ground truth LLM traffic was established via explicit endpoint labeling at capture time using DNS and TLS SNI metadata. TLS application-data records exchanged with labeled endpoints were treated as LLM traffic, and flowlets were derived by grouping records using inter-record timing gaps. This approach preserves ground-truth labeling while removing transport-layer artifacts introduced by packetization.”