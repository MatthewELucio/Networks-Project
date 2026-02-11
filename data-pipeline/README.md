# Data Pipeline

This directory contains scripts for data collection, processing, and flowlet extraction.

## Scripts

### Flowlet Parsing

#### `parse_flowlets_encrypted.py`
Parses encrypted network captures (tcpdump-style text) into flows and flowlets.

**Usage:**
```bash
# Parse a single capture file
python parse_flowlets_encrypted.py capture.txt --threshold 0.1 --output flowlets.json

# Parse a directory of captures
python parse_flowlets_encrypted.py captures/ --pattern "capture*.txt" --threshold 0.1 --output flowlets.json

# Extract features for ML training
python parse_flowlets_encrypted.py --extract-features \
    --captures-root ../captures \
    --features-output flowlet_features.json \
    --threshold 0.1
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
python parse_flowlets_decrypted.py --input ../captures/chatgpt_ipv4 --db --db-path ../data/networks_project.db

# Parse captures and save to JSON
python parse_flowlets_decrypted.py --input ../captures/chatgpt_ipv4 --output flowlets.json --threshold 0.1
```

**Features:**
- Reads `LLM_IP <LLM_NAME> <IP_ADDRESS>` headers from captures
- Tags flowlets with ground truth LLM provider labels
- Saves to SQLite database or JSON format
- Supports bidirectional flow grouping

### Database

#### `database.py`
SQLAlchemy models and utilities for storing captures and flowlets in SQLite.

**Models:**
- `Capture`: Represents a packet capture file
- `Flowlet`: Represents a flowlet extracted from a capture

**Usage:**
```python
from database import init_database, get_db_session, Capture, Flowlet

# Initialize database
init_database("data/networks_project.db")

# Get a session
db = get_db_session()

# Query flowlets
flowlets = db.query(Flowlet).filter_by(traffic_class="llm").all()
```

### Data Collection

#### `ip_range_capture.py`
Captures network traffic for specific IP ranges.

**Usage:**
```bash
python ip_range_capture.py
```

#### `ip_range_capture_with_llm.py`
Captures network traffic for specific IP ranges with LLM interaction support.

**Usage:**
```bash
python ip_range_capture_with_llm.py
```

#### `pcap_to_txt.py`
Converts PCAP files to text format for parsing.

**Usage:**
```bash
python pcap_to_txt.py <input.pcap> <output.txt>
```

#### `selenium_bot_llm.py`
Selenium-based bot for automated LLM interaction and traffic capture.

#### `generate_prompt_bank.py`
Generates diverse prompts for LLM testing.

#### `prepare_prompt_runner.py`
Prepares and runs prompt sequences for data collection.

## Directory Structure

```
data-pipeline/
├── README.md                          # This file
├── parse_flowlets_encrypted.py        # Parse encrypted captures
├── parse_flowlets_decrypted.py        # Parse decrypted captures with LLM tagging
├── database.py                        # Database models and utilities
├── ip_range_capture.py                # IP range capture utility
├── ip_range_capture_with_llm.py       # IP range capture with LLM support
├── pcap_to_txt.py                     # PCAP to text converter
├── selenium_bot_llm.py                # Automated LLM interaction
├── generate_prompt_bank.py            # Prompt generation
├── prepare_prompt_runner.py           # Prompt runner
├── prompt_bank.json                   # Generated prompts
└── non-llm/                           # Non-LLM traffic collection scripts
```

## Related Directories

- `../captures/`: Network capture files organized by LLM provider
- `../packet-analysis/`: ML models and classification scripts
