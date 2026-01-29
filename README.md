# Networks-Project

CS 7457 research project authored by Gavin Crigger, Tao Groves, Matthew Lucio, and Sebastian Wiktorowicz

## File Structure

### Data-pipeline directory

The 'data-pipeline' directory is the location for our working, updated data pipeline that streamlines traffic captures for both LLM and non-LLM traffic. It contains a 'generate_prompt_bank.py' script that takes an OpenAI LLM key (alongside some other parameters) to generate and load a large number of prompt chains across many categories to a flat-file database. This is intended to create prompts similar to everyday LLM usage that will thus give us the most realistic traffic while still allowing us to automate data collection at a large scale. The 'prepare_prompt_runner.py' file is used to load in these prompts to then be passed to browser-based LLM services via Selenium, all with traffic being captured and stored. At the current moment, this script is formatted to query an OpenAI API endpoint (which will then be replaced with the Selenium part of the pipeline).

For non-LLM traffic, we employ a data pipeline methodology based on [Qian et. al's work][https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=10606298&tag=1]. That is, we access a list of popular URLs via a traffic ranking website, access the URLs with an automated browser tool, deploy a pcap tool, stop captures when the page loads, and process the data. *This is still to be implemented.*

### Captures directory

The 'captures' directory houses subdirectories that each contain corresponding packet captures. The 'all' directories have captures of all traffic on an interface and should be used as non-LLM flow data. The 'chatgpt', 'gemini', and 'claude' directories all contain captures of LLM-specific data for one set of interactions corresponding to a single IP address. Thus, these captures each represent one flow and contain many flowlets (exact number depends on selected threshold). Furthermore, capture names end with a general description of the queries that took place to hopefully allow for insight into any anomalous data. Finally, 'ipv4' and 'ipv6' simply distinguishes between the IP version that the captures correspond to - all eduroam packet captures are in ipv4 folders.

### Front-end directory

The front-end provides a web-based interface for managing packet captures and analyzing network traffic. The system uses a SQLite database to store captures and flowlets, replacing the previous JSON-based approach.

#### Setup and Running

1. **Start the API server:**
   ```bash
   python api_server.py
   # Or with auto-reload: uvicorn api_server:app --reload
   ```
   The API server runs on `http://localhost:8000` and manages the SQLite database (`data/networks_project.db`).

2. **Start the front-end:**
   ```bash
   cd front-end
   npm install
   npm run dev
   ```
   The front-end runs on `http://localhost:5173` (Vite default port).

3. **Or with Docker:**

  ```bash
  docker compose down
  docker compose up --build
  ```

#### Features

- **Capture Management**: View all captures in a table with flow counts and LLM flow counts (after classification)
- **Start Captures**: Click "Start Capture" to open a dialog for configuring capture parameters:
  - IP range (CIDR notation)
  - Network interface
  - Output directory
  - Timeout
  - Snap length
  - Extra filters
  - **SSL Decryption**: Check "Use SSL Decryption" to decrypt TLS traffic (requires SSL keys configuration)
- **SSL Keys Configuration**: Click "SSL Keys" button to configure the path to your SSLKEYLOGFILE for TLS decryption
- **Parse Captures**: Click "Parse" button to extract flowlets from capture files and store them in the database
- **Run Classification**: Click "Classify" button to run ML models on flowlets and generate predictions
- **Capture Details**: Click on any capture to view:
  - Time-series chart of flow patterns (total bytes vs LLM bytes)
  - **Predicted vs Actual table**: Compare model predictions against ground truth from decrypted captures
    - Shows ground truth LLM (from decrypted captures)
    - Shows model prediction and confidence
    - Indicates match/mismatch with visual indicators


### Packet-analysis directory

The packet-analysis directory contains machine learning models for classifying LLM vs non-LLM network traffic. Follow these steps to analyze packet captures:

#### Dependencies

```bash
pip install -r requirements.txt
```

This installs all required dependencies including:
- Machine learning libraries (numpy, scikit-learn, xgboost, scipy)
- Visualization tools (matplotlib, seaborn)
- Web server (fastapi, uvicorn)
- Database (sqlalchemy)
- Model serialization (joblib)

#### Step 1: Parse Captures into Flowlets

**Option A: Using the Web Interface (Recommended)**
1. Start the API server and front-end (see Front-end directory section)
2. Click "Parse" button on any completed capture in the web interface
3. Flowlets are automatically saved to the SQLite database

**Option B: Using Command Line**

```bash
# Parse captures and save to database
python packet-analysis/parse_flowlets_v2.py --input captures/chatgpt_ipv4 --db --db-path networks_project.db --threshold 0.1

# Or save to JSON (legacy format)
python packet-analysis/parse_flowlets_v2.py --input captures/chatgpt_ipv4 --output flowlet_features.json --threshold 0.1
```

**Input**: Raw packet captures in `captures/` directory  
**Output**: 
- Flowlets saved to SQLite database (`data/networks_project.db`) with foreign keys to captures
- If using decrypted captures (with `LLM_IP` headers), ground truth LLM names are automatically extracted and stored in `ground_truth_llm` field
- Optional: `flowlet_features.json` for legacy workflows

#### Step 2: Run Classification

**Option A: Using the Web Interface (Recommended)**
1. After parsing a capture, click "Classify" button
2. Classification runs in the background and updates flowlets with predictions
3. View results in the capture detail view

**Option B: Using Command Line**

```bash
# Classify flowlets from database
python packet-analysis/classify.py --input data/networks_project.db --input-type sql --sql-query "SELECT * FROM flowlets WHERE capture_id = 1" --model-weights packet-analysis/flowlet_model_weights.pkl

# Or classify from JSON (legacy)
python packet-analysis/classify.py --input flowlet_features.json --model-weights packet-analysis/flowlet_model_weights.pkl --output classified_flowlets.json
```

**Input**: Flowlets from database or JSON file  
**Output**: Flowlets updated with `model_llm_prediction` and `model_llm_confidence` fields

#### Step 3: Train Classification Models

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

#### Step 4: Generate Analysis Plots

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

## Capture Scripts

### ip_range_capture.py

This script is the primary data-collection method. Invoking `ip_range_capture.py` with a specified IP address or range begins a tcpdump into a .txt file with that range/address applied as a filter. The general workflow:

1. Open Wireshark and an LLM browser interface
2. Issue some long request to the LLM
3. Observe Wireshark traffic to identify the IP address streaming the LLM's response to the device
   - This became easy with time, as LLM flows have a pretty identifiable pattern among the noise of our device connections.
4. Invoke the python script with: `sudo python3 ip_range_capture.py <IP_ADDRESS>`
5. Issue queries to LLM
6. Terminate packet collection with Ctrl+C when done issuing queries or the connection switches off of the specified IP address (when a FIN ACK appears in the Wireshark capture)

Output captures are saved with the naming convention: `capture_<DATE>_<TIME>_<IP>_<ADDRESS_SIZE>.txt`

### ip_range_capture_tshark_decrypt_llm_only.py

This script extends the basic capture functionality with TLS decryption capabilities. It uses tshark to decrypt TLS traffic when SSL keys are provided, and automatically identifies LLM traffic by detecting keywords in hostnames, SNI, DNS queries, and HTTP headers.

**Features:**
- Decrypts TLS traffic using SSLKEYLOGFILE
- Automatically detects LLM traffic (ChatGPT, Claude, Gemini, etc.)
- Outputs captures with `LLM_IP` headers indicating which IPs belong to which LLM
- These headers are used as ground truth when parsing flowlets

**Usage:**
```bash
python ip_range_capture_tshark_decrypt_llm_only.py <IP_RANGE> -k /path/to/sslkeylogfile.txt --sniff
```

**Via Web Interface:**
1. Configure SSL keys in the front-end (click "SSL Keys" button)
2. Start a capture with "Use SSL Decryption" checked
3. The script automatically uses the configured SSL keys

**Output Format:**
- Captures start with `LLM_IP <LLM_NAME> <IP_ADDRESS>` headers
- These headers are parsed by `parse_flowlets_v2.py` to set `ground_truth_llm` field
- Enables comparison of model predictions against actual LLM traffic

## Database Schema

The system uses SQLite with the following main tables:

- **captures**: Stores capture file metadata
  - `id`, `file_path`, `created_at`, `status`, `llm_ip_map`, `notes`
  
- **flowlets**: Stores extracted flowlet features
  - `id`, `capture_id` (foreign key), flow key fields, timing, packet/byte counts, statistics
  - `model_llm_prediction`: ML model prediction (set by `classify.py`)
  - `model_llm_confidence`: Confidence score for prediction
  - `ground_truth_llm`: Actual LLM from decrypted captures (set when parsing captures with `LLM_IP` headers)

The database file (`networks_project.db`) is automatically created when the API server starts.

## API Endpoints

The API server provides the following endpoints:

- `GET /api/captures` - List all captures with flow counts
- `GET /api/captures/{id}` - Get capture details
- `GET /api/captures/{id}/flowlets` - Get flowlets for a capture
- `GET /api/captures/{id}/flowlets/chart` - Get chart data (time series)
- `POST /api/captures/start` - Start a new capture
- `POST /api/captures/{id}/stop` - Stop a running capture
- `POST /api/captures/{id}/parse` - Parse a capture file
- `POST /api/captures/{id}/classify` - Run classification on flowlets
- `GET /api/ssl-keys` - Get SSL keys configuration
- `POST /api/ssl-keys` - Set SSL keys configuration

See the API server code (`api_server.py`) for detailed request/response formats.


# 🔐 Setting Up SSL Decryption

To allow the application to analyze encrypted HTTPS traffic (e.g., traffic to LLMs like ChatGPT), you must configure your browser to log its SSL/TLS keys to a file that our Docker container can read.

### Step 1: Set the Environment Variable
You need to tell your browser where to save the keys. We will set this to be **inside this project folder**.

#### 🪟 For Windows Users
1.  Open the **Start Menu**, search for **"Edit environment variables for your account"**, and press Enter.
2.  In the "User variables" section (top half), click **New**.
3.  **Variable name:** `SSLKEYLOGFILE`
4.  **Variable value:** Browse to this project's folder, and append `\data\sslkeylogfile.txt` to the end.
    * *Example:* `C:\Users\You\Documents\Networks-Project\data\sslkeylogfile.txt`
5.  Click **OK** to save.

#### 🍎/🐧 For Mac & Linux Users
Run the following command in your terminal **inside the project root directory**:

```bash
# Add this to your shell profile (.zshrc or .bashrc) to make it permanent
export SSLKEYLOGFILE=$(pwd)/data/sslkeylogfile.txt
```

### Step 2: Restart Browser
Completely quit Chrome/Edge (ensure it is not running in the background) and reopen it.

### Step 3: Verify
Visit a website. Check your project folder in data for a file named sslkeylogfile.txt.



# 