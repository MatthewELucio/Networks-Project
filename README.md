# Networks-Project

CS 7457 research project authored by Gavin Crigger, Tao Groves, Matthew Lucio, and Sebastian Wiktorowicz

## File Structure

### Captures directory

The 'captures' directory houses subdirectories that each contain corresponding packet captures. The 'all' directories have captures of all traffic on an interface and should be used as non-LLM flow data. The 'chatgpt', 'gemini', and 'claude' directories all contain captures of LLM-specific data for one set of interactions corresponding to a single IP address. Thus, these captures each represent one flow and contain many flowlets (exact number depends on selected threshold). Furthermore, capture names end with a general description of the queries that took place to hopefully allow for insight into any anomalous data. Finally, 'ipv4' and 'ipv6' simply distinguishes between the IP version that the captures correspond to - all eduroam packet captures are in ipv4 folders.

### Front-end directory

The front-end provides a web-based interface for managing packet captures and analyzing network traffic. To use it, first start the API server with `python api_server.py` (or `uvicorn api_server:app --reload`), then navigate to the `front-end` directory and run `npm install` followed by `npm run dev`. The interface displays a table of all captures with flow counts and LLM flow counts (after classification), allows you to start new captures via a popup dialog that configures `ip_range_capture.py` arguments (IP range, interface, timeout, etc.), and provides buttons to parse capture files and run classification. Clicking on any capture opens a detailed view showing a time-series chart of flow patterns (total bytes vs LLM bytes) that updates in real-time, enabling visual analysis of traffic patterns over the capture duration.


### Packet-analysis directory

The packet-analysis directory contains machine learning models for classifying LLM vs non-LLM network traffic. Follow these steps to analyze packet captures:

#### Dependencies

```bash
pip install numpy scikit-learn xgboost matplotlib seaborn scipy
```

#### Step 1: Parse Captures into Flowlets

```bash
python packet-analysis/parse_flowlets.py --extract-features --captures-root captures --features-output flowlet_features.json --threshold 0.1
```

**Input**: Raw packet captures in `captures/` directory  
**Output**: `flowlet_features.json` - Extracted flowlet features for ML training

#### Step 2: Train Classification Models

```bash
# For ChatGPT detection
python packet-analysis/chatgpt/flowlet_models.py flowlet_features.json --output model_results.json

# For Gemini detection
python packet-analysis/gemini/flowlet_models_gemini.py flowlet_features.json --output model_results_gemini.json

# For Claude detection
python packet-analysis/claude/flowlet_models_claude.py flowlet_features.json --output model_results_claude.json
```

**Input**: `flowlet_features.json`  
**Output**: `model_results.json` - Model performance metrics and confusion matrices

#### Step 3: Generate Analysis Plots

```bash
# For ChatGPT analysis
python packet-analysis/chatgpt/flowlet_analysis.py flowlet_features.json --output analysis_results.json --output-dir analysis_plots

# For Gemini analysis
python packet-analysis/gemini/flowlet_analysis_gemini.py flowlet_features.json --output analysis_results_gemini.json --output-dir analysis_plots_gemini

# For Claude analysis
python packet-analysis/claude/flowlet_analysis_claude.py flowlet_features.json --output analysis_results_claude.json --output-dir analysis_plots_claude
```

**Input**: `flowlet_features.json`  
**Output**:

- `analysis_results.json` - Feature correlation and importance analysis
- `analysis_plots/` - Visualization plots (heatmaps, distributions, importance charts)

## ip_range_capture.py

This script is the primary data-collection method that we used. Invoking ip_range_capture.py with a specified IP address or range begins a tcpdump into a .txt file with that range/address applied as a filter. The general workflow that we used was:

1. Open Wireshark and an LLM browser interface
2. Issue some long request to the LLM
3. Observe Wireshark traffic to identify the IP address streaming the LLM's response to the device
   - This became easy with time, as LLM flows have a pretty identifiable pattern among the noise of our device connections.
4. Invoke the python script with: _sudo python3 ip_range_capture.py <IP_ADDRESS>_
5. Issue queries to LLM
6. Terminate packet collection with Ctrl+C when done issuing queries or the connection switches off of the specified IP address (when a FIN ACK appears in the Wireshark capture)

Output captures were then moved to their corresponding directory, and the default naming convention of captures was _capture*<DATE>*<TIME>*<IP>*<ADDRESS_SIZE>.txt_ - we then manually added qualitative notes to the end of the file name.
