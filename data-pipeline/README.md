# Data Pipeline

This directory contains scripts for data collection, processing, and flowlet extraction.

## Database Structure
The MongoDB document schema is organized at the capture level: each capture is stored as one document in the captures collection, keyed by the capture’s file\_path. The top-level document includes creation timestamp, a status field, an llm\_ip\_map structure for mapping observed endpoints to LLM names, and optional notes. Finally, each document embeds an array field flowlets, where every flowlet is represented as a subdocument containing its flow identity (including flow\_key such as src\_ip, src\_port, dst\_ip, dst\_port, and protocol), a sequential flowlet\_id, traffic annotations like traffic\_class and llm\_name, directionality features (outgoing and direction\_encoded), and timing/size statistics such as start\_ts, end\_ts, duration, packet\_count, total\_bytes, plus mean and standard deviation features for inter-packet times and packet sizes. The schema also supports model training artifacts through prediction fields (e.g., model\_llm\_prediction, model\_llm\_confidence) and optional supervision (ground\_truth\_llm). For space efficiency, the user may omit or default longer sequence arrays (e.g., raw per-packet sequences) while preserving aggregated statistics, as the former were unnecessary to obtain the results presented.

Snapshotting for model training is performed by exporting selected subsets of the cloud MongoDB collection into a local filesystem representation. A snapshot script connects to the MongoDB instance and writes an output directory containing a manifest.json file (capturing the export metadata such as the query and export time) and a captures/ subdirectory with one JSON file per capture document (<capture\_id>.json). Because the JSON files are written via json.dump(doc, ...), the snapshot preserves the nested document structure of the flowlets array, including all feature fields and any model labels contained in the stored documents. The snapshot tool supports filtering by created\_at ranges, LLMs found in the capture, and the flowlet partition threshold fields using MongoDB’s query expressions; this allows researchers to align training data selection with capture collection parameters. In this way, researchers can train models offline against a stable, versionable local snapshot of the cloud database.

## Directory Structure

```
data-pipeline/
├── README.md                          # This file
├── ip-capture-scripts/                # Network capture utilities
│   ├── ip_range_capture.py
│   ├── ip_range_capture_with_llm.py
│   └── pcap_to_txt.py
├── data-collection/                   # Automated data collection
│   ├── llm/                          # LLM interaction automation
│   │   ├── selenium_bot_llm_chrome.py
│   │   ├── selenium_bot_llm_firefox.py
│   │   ├── generate_prompt_bank.py
│   │   ├── prepare_prompt_runner.py
│   │   └── prompt_bank.json
│   └── non-llm/                      # Non-LLM traffic collection
│       └── collect_non_llm_data.py
└── flowlet-parsing/                   # Data processing and transformation
    ├── parse_flowlets_encrypted.py
    ├── parse_flowlets_decrypted.py
    └── database.py
```

## Scripts

### Network Capture (ip-capture-scripts/)

#### `ip_range_capture.py`
Captures network traffic for specific IP ranges using tcpdump.

**Usage:**
```bash
sudo python3 ip-capture-scripts/ip_range_capture.py <IP_ADDRESS>
```

#### `ip_range_capture_with_llm.py`
Captures network traffic with TLS decryption and automatic LLM detection.

**Usage:**
```bash
python ip-capture-scripts/ip_range_capture_with_llm.py <IP_RANGE> -k /path/to/sslkeylogfile.txt --sniff
```

**Features:**
- Decrypts TLS traffic using SSLKEYLOGFILE
- Automatically detects LLM traffic (ChatGPT, Claude, Gemini, etc.)
- Outputs captures with `LLM_IP` headers for ground truth labeling

### Data Collection (data-collection/)

#### LLM Collection (data-collection/llm/)

##### `selenium_bot_llm_firefox.py`
Selenium-based bot for automated LLM interaction and traffic capture.

##### `selenium_bot_llm_chrome.py`
Selenium-based bot for automated LLM interaction and traffic capture on Chrome (set ssl keys environment variable: SSLKEYLOGFILE) for chatgpt, gemini, or claude (requires logging in first).

**Usage:**
```bash
python data-collection/llm/selenium_bot_llm_chrome.py --target <PROVIDER> --prompts <PROMPT_FILE> # (default is prompt_back.json)
```

##### `generate_prompt_bank.py`
Generates diverse prompts for LLM testing.

##### `prepare_prompt_runner.py`
Prepares and runs prompt sequences for data collection.

#### Non-LLM Collection (data-collection/non-llm/)

##### `collect_non_llm_data.py`
Collects non-LLM network traffic for baseline comparison.

### Flowlet Parsing (flowlet-parsing/)

#### `parse_flowlets_encrypted.py`
Parses encrypted network captures (tcpdump-style text) into flows and flowlets.

**Usage:**
```bash
# Parse a single capture file
python flowlet-parsing/parse_flowlets_encrypted.py capture.txt --threshold 0.1 --output flowlets.json

# Parse a directory of captures
python flowlet-parsing/parse_flowlets_encrypted.py captures/ --pattern "capture*.txt" --threshold 0.1 --output flowlets.json

# Extract features for ML training
python flowlet-parsing/parse_flowlets_encrypted.py --extract-features \
    --captures-root ../captures \
    --features-output flowlet_features.json \
    --threshold 0.1

# Live capture to DB (creates 3 captures with suffixes _0.05, _0.1, _0.2)
python flowlet-parsing/live_capture_to_db.py --cloud-db -k ~/mnt/c/Users/matth/Documents/sslkeys.txt -t 30 -i Wi-Fi -n my_capture 0.0.0.0/0

# Resume an existing live capture run (IDs must be in threshold order: 0.05,0.1,0.2)
python flowlet-parsing/live_capture_to_db.py --cloud-db -k ~/mnt/c/Users/matth/Documents/sslkeys.txt -t 30 -i Wi-Fi -n my_capture --capture-id id1,id2,id3 0.0.0.0/0
```

**Features:**
- Splits packet flows into flowlets based on inter-packet gap threshold
- Computes statistical features (packet sizes, inter-packet times, etc.)
- Infers traffic direction (client-to-server vs server-to-client)
- Exports to JSON format for ML training

#### `parse_flowlets_decrypted.py`
Parses decrypted network captures with LLM IP tagging for ground truth labeling.

**Usage:**
```bash
# Parse captures and save to database
python flowlet-parsing/parse_flowlets_decrypted.py --input ../captures/chatgpt_ipv4 --db --db-path ../data/networks_project.db

# Parse captures and save to JSON
python flowlet-parsing/parse_flowlets_decrypted.py --input ../captures/chatgpt_ipv4 --output flowlets.json --threshold 0.1
```

**Features:**
- Reads `LLM_IP <LLM_NAME> <IP_ADDRESS>` headers from captures
- Tags flowlets with ground truth LLM provider labels
- Saves to SQLite database or JSON format
- Supports bidirectional flow grouping

#### `database.py`
SQLAlchemy models and utilities for storing captures and flowlets in SQLite.

**Models:**
- `Capture`: Represents a packet capture file
- `Flowlet`: Represents a flowlet extracted from a capture

**Usage:**
```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "data-pipeline" / "flowlet-parsing"))
from database import init_database, get_db_session, Capture, Flowlet

# Initialize database
init_database("data/networks_project.db")

# Get a session
db = get_db_session()

# Query flowlets
flowlets = db.query(Flowlet).filter_by(traffic_class="llm").all()
```

## Pipeline Workflow

The data pipeline follows this flow:

1. **Capture** (ip-capture-scripts/) - Collect raw network traffic
2. **Collection** (data-collection/) - Automate LLM interactions and traffic generation
3. **Parsing** (parsing/) - Convert captures to structured flowlet data
4. **Analysis** (../packet-analysis/) - ML classification and analysis

## Related Directories

- `../captures/`: Network capture files organized by LLM provider
- `../packet-analysis/`: ML models and classification scripts
