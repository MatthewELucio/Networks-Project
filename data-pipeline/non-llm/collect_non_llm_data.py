"""
collect_non_llm_data.py

Automated pipeline for collecting non-LLM website traffic data for fingerprinting research.

Features:
- Fetches top URLs from Tranco (Alexa alternative)
- Uses Selenium to automate browser visits (cache disabled)
- Captures raw network traffic with tcpdump
- Stops capture after page load
- Stores pcap for later processing
- Intended to match Qian et al. (2024) methodology (no noise injection)

Sample Run Command:
    sudo python3 collect_non_llm_data.py --num-urls 100 --output-dir ../../captures/non_llm/

This will visit the top 100 Tranco sites, saving a pcap for each in captures/non_llm/.
Adjust --num-urls and --output-dir as needed.

Dependencies:
    - selenium
    - requests
    - tqdm
    - tcpdump (system)
    - Google Chrome or Firefox
    - chromedriver or geckodriver

"""
import argparse
import os
import subprocess
import time
import socket
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException
from tqdm import tqdm
from pathlib import Path

TRANCO_LIST_URL = "https://tranco-list.eu/top-1m.csv.zip"


def fetch_tranco_top_sites(n=100):
    """Download and parse the Tranco top sites list (CSV). Returns list of domains."""
    import zipfile
    import io
    resp = requests.get(TRANCO_LIST_URL)
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        with zf.open(zf.namelist()[0]) as f:
            lines = f.read().decode().splitlines()
    domains = [line.split(',')[1] for line in lines[1:n+1]]  # skip header
    return domains


def start_tcpdump_capture(output_file, interface="en0"):
    """Start tcpdump capture as a subprocess. Returns the process handle."""
    cmd = [
        "sudo", "tcpdump", "-i", interface, "-w", output_file, "-U"
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def stop_tcpdump_capture(proc):
    """Terminate tcpdump process."""
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def visit_url_with_selenium(url, driver, timeout=20):
    """Visit a URL and wait for page load. Returns True if successful, False otherwise."""
    try:
        driver.set_page_load_timeout(timeout)
        driver.get(url)
        time.sleep(5)  # Wait for network to settle
        return True
    except Exception as e:
        print(f"Selenium error visiting {url}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Collect non-LLM website traffic data.")
    parser.add_argument("--num-urls", type=int, default=100, help="Number of top URLs to visit.")
    parser.add_argument("--output-dir", type=str, required=True, help="Directory to store pcap files.")
    parser.add_argument("--interface", type=str, default="en0", help="Network interface for tcpdump.")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    domains = fetch_tranco_top_sites(args.num_urls)

    # Set up Selenium (Chrome, cache disabled)
    chrome_options = Options()
    chrome_options.add_argument("--incognito")
    chrome_options.add_argument("--disable-application-cache")
    chrome_options.add_argument("--disk-cache-size=1")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--headless=new")
    driver = webdriver.Chrome(options=chrome_options)

    for i, domain in enumerate(tqdm(domains, desc="Visiting sites")):
        url = f"https://{domain}"
        # DNS resolution check
        try:
            socket.gethostbyname(domain)
        except Exception:
            print(f"[{i+1}/{len(domains)}] {domain}: SKIPPED (DNS resolution failed)")
            continue
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        pcap_file = os.path.join(args.output_dir, f"capture_{timestamp}_{domain}.pcap")
        proc = start_tcpdump_capture(pcap_file, interface=args.interface)
        success = visit_url_with_selenium(url, driver)
        stop_tcpdump_capture(proc)
        print(f"[{i+1}/{len(domains)}] {domain}: {'OK' if success else 'FAILED'} -> {pcap_file}")
        time.sleep(2)  # Small delay between sites

    driver.quit()
    print("Done. PCAPs saved to", args.output_dir)

if __name__ == "__main__":
    main()
