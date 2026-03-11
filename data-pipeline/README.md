# Data Pipeline

This directory contains scripts for data collection, processing, and flowlet extraction.

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

python live_capture_to_db.py -o captures -k ~/mnt/c/Users/matth/Documents/sslkeys.txt -t 30 -i Wi-Fi 0.0.0.0/0 
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
