# Packet Analysis - LLM Traffic Classification

Parsing based on TLS records

## TLS Flowlet Pipeline (Summary)

### Input
- `capture_*.pcap`  
  Raw packet capture containing TLS traffic.

- `capture_*.txt`  
  Text capture with ground-truth endpoint labels:
LLM_IP <LLM_NAME> <LLM_SERVER_IP>


### Output
- `capture_*.tls.tsv`  
Derived TLS application-record stream (one per capture).

- `flowlets_tls.json`  
Combined JSON file containing TLS-record flowlet features.

---

### How It Works
1. **TLS Record Extraction**  
 TLS application-data records are extracted from the pcap using `tshark`.  
 Each record includes timestamp, endpoints, TCP stream ID, and TLS record size.

2. **Flowlet Construction**  
 TLS records are grouped by TCP stream and split into flowlets based on inter-record time gaps.

3. **Ground Truth Labeling**  
 Flowlets involving IPs declared in `LLM_IP` headers are labeled as LLM traffic.  
 Direction is inferred from endpoint roles (client ↔ LLM server).

4. **Feature Output**  
 Flowlet-level timing, size, and direction features are written to JSON for analysis or ML.

---

### Notes
- TLS decryption is **not required**.
- Ground truth is inherited from capture-time labels.
- TLS flowlets replace packet observations with TLS application records.


