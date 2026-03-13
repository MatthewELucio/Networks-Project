# MAWI-captures
This directory contains all files relevant to parsing in captures from the MAWI project - the majority of these files are gitignored due to massive size.

## Multi-threshold behavior

Both MAWI parsers now use fixed flowlet thresholds and always write separate capture documents per threshold:

- `0.05`
- `0.1`
- `0.2`

For a source capture ID like `202101021400`, outputs are:

- `202101021400_0.05`
- `202101021400_0.1`
- `202101021400_0.2`

This avoids the prior single-session overwrite issue seen in other pipelines by writing each threshold to its own document key.

#### `parse_MAWI_parallel.py`
Downloads MAWI traces across a date range and parses/uploads in parallel.

**Usage:**
```bash
python MAWI-captures/parse_MAWI_parallel.py \
	--start 2021-01-01 \
	--end 2021-01-07 \
	--step-days 1 \
	--max-packets 2000 \
	--workers 8
```

#### `parse_MAWI.py`
Processes a single MAWI URL.

**Usage:**
```bash
python MAWI-captures/parse_MAWI.py \
	http://mawi.nezu.wide.ad.jp/mawi/samplepoint-F/2021/202101021400.pcap.gz \
	--max-packets 2000
```

#### `pcap_to_txt.py`
Converts PCAP files to text format for parsing.

**Usage:**
```bash
python ip-capture-scripts/pcap_to_txt.py <input.pcap> <output.txt>
```