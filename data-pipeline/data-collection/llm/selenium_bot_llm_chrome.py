import undetected_chromedriver as uc
import time
import random
import argparse
import os
import json
import sys
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from pathlib import Path
from dotenv import load_dotenv

# Example usage: 
# cd data-pipeline\data-collection\llm
# python .\selenium_bot_llm_chrome.py --target chatgpt

# --- CONFIGURATION ---
# Set SSL Keylog file for Wireshark decryption
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent.parent.parent
env_path = project_root / ".env"
load_dotenv(dotenv_path=env_path, override=True)

LLM_CONFIG = {
    "chatgpt": {
        "url": "https://chatgpt.com",
        "input_selector": "#prompt-textarea",
        "submit_selector": "button[data-testid='send-button']",
        "enter_key": True,
    },
    "claude": {
        "url": "https://claude.ai",
        "input_selector": "div[contenteditable='true']",
        "submit_selector": "button[aria-label='Send Message']",
        "enter_key": True,
    },
    "gemini": {
        "url": "https://gemini.google.com",
        "input_selector": "div[role='textbox']",
        "submit_selector": "button[aria-label='Send message']",
        "enter_key": True, 
    }
}

# --- PATCH START ---
# Fix for "OSError: [WinError 6] The handle is invalid" on Windows
def _suppress_win_error(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except OSError as e:
            if e.errno == 6: pass
            else: raise
    return wrapper

uc.Chrome.quit = _suppress_win_error(uc.Chrome.quit)
# --- PATCH END ---

def load_prompt_bank(filepath):
    """Loads the conversation scenarios from a JSON file."""
    if not os.path.exists(filepath):
        print(f"❌ Error: Prompt bank file not found at: {filepath}")
        sys.exit(1)
    
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def random_sleep(min_s=1.5, max_s=4.0):
    time.sleep(random.uniform(min_s, max_s))

def type_like_human(element, text):
    """Types text one character at a time with random delays."""
    for char in text:
        element.send_keys(char)
        time.sleep(random.uniform(0.01, 0.04)) # Slightly faster typing

def get_driver():
    """Initializes the undetected_chromedriver."""
    print("🚀 Launching Undetected Chrome...")
    options = uc.ChromeOptions()
    # options.add_argument("--headless") # DO NOT USE HEADLESS
    
    driver = uc.Chrome(options=options, use_subprocess=True, version_main=146)
    return driver

# def run_bot(target_name, prompt_bank_path):
#     if target_name not in LLM_CONFIG:
#         print(f"❌ Unknown target: {target_name}. Available: {list(LLM_CONFIG.keys())}")
#         return

#     # Load prompts
#     scenarios = load_prompt_bank(prompt_bank_path)
#     print(f"📂 Loaded {len(scenarios)} scenarios from {prompt_bank_path}")

#     config = LLM_CONFIG[target_name]
#     driver = get_driver()

#     try:
#         print(f"🌐 Navigating to {target_name.upper()}...")
#         driver.get(config["url"])

#         # Manual Login / Cloudflare Pause
#         print("\n" + "="*60)
#         print(f"⚠️  ACTION REQUIRED: Please LOG IN to {target_name.upper()} manually.")
#         print("👉  Press ENTER in this terminal once you are ready to send prompts...")
#         print("="*60 + "\n")
#         input()

#         print("🤖 Bot Active. Starting conversation loops (Ctrl+C to stop)...")
        
#         while True:
#             # 1. Pick a random scenario (conversation chain)
#             scenario = random.choice(scenarios)
#             category = scenario.get("category", "Unknown")
#             prompts = scenario.get("prompts", [])
            
#             print(f"\n🎭 Starting New Scenario: '{category}' ({len(prompts)} turns)")

#             # 2. Loop through each prompt in the chain
#             for i, prompt in enumerate(prompts):
#                 print(f"   ➡ Turn {i+1}/{len(prompts)}: '{prompt[:50]}...'")

#                 try:
#                     # Find Input Box
#                     # We re-find it every turn because the DOM might change after a message is sent
#                     input_box = WebDriverWait(driver, 20).until(
#                         EC.element_to_be_clickable((By.CSS_SELECTOR, config["input_selector"]))
#                     )
#                     input_box.click()
                    
#                     # Type Prompt
#                     type_like_human(input_box, prompt)
#                     random_sleep(0.5, 1.5)

#                     # Submit
#                     if config["enter_key"]:
#                         input_box.send_keys(Keys.ENTER)
#                     else:
#                         submit_btn = driver.find_element(By.CSS_SELECTOR, config["submit_selector"])
#                         submit_btn.click()

#                     # Wait for Response (Simulate reading time)
#                     # Variable wait: longer for first prompts, shorter for follow-ups
#                     wait_time = random.randint(15, 30)
#                     print(f"      ⏳ Waiting {wait_time}s for response/reading...")
#                     time.sleep(wait_time)

#                 except Exception as e:
#                     print(f"⚠️ Error in turn {i+1}: {e}")
#                     time.sleep(5)
            
#             # End of Scenario Delay
#             inter_scenario_wait = random.randint(10, 20)
#             print(f"✅ Scenario '{category}' complete. Taking a break for {inter_scenario_wait}s...")
#             time.sleep(inter_scenario_wait)

#     except KeyboardInterrupt:
#         print("\n🛑 Bot stopped by user.")
#     except Exception as e:
#         print(f"❌ Fatal Error: {e}")
#     finally:
#         print("👋 Closing browser...")
#         driver.quit()

def run_bot(target_name, prompt_bank_path):
    if target_name not in LLM_CONFIG:
        print(f"❌ Unknown target: {target_name}. Available: {list(LLM_CONFIG.keys())}")
        return

    # Load prompts
    scenarios = load_prompt_bank(prompt_bank_path)
    print(f"📂 Loaded {len(scenarios)} scenarios from {prompt_bank_path}")

    if not scenarios:
        print("❌ Error: Prompt bank is empty.")
        return

    config = LLM_CONFIG[target_name]
    driver = get_driver()

    try:
        print(f"🌐 Navigating to {target_name.upper()}...")
        driver.get(config["url"])

        # Manual Login / Cloudflare Pause
        print("\n" + "="*60)
        print(f"⚠️  ACTION REQUIRED: Please LOG IN to {target_name.upper()} manually.")
        print("👉  Press ENTER in this terminal once you are ready to send prompts...")
        print("="*60 + "\n")
        input()

        print("🤖 Bot Active. Starting SEQUENTIAL prompt loop (Ctrl+C to stop)...")
        
        scenario_index = 0
        
        while True:
            # 1. Select the next scenario in order
            scenario = scenarios[scenario_index]
            category = scenario.get("category", "Unknown")
            prompts = scenario.get("prompts", [])
            
            print(f"\n🎭 Starting Scenario {scenario_index + 1}/{len(scenarios)}: '{category}'")

            # 2. Loop through each prompt in the chain
            for i, prompt in enumerate(prompts):
                print(f"   ➡ Turn {i+1}/{len(prompts)}: '{prompt[:50]}...'")

                try:
                    # Find Input Box
                    # We re-find it every turn because the DOM might change after a message is sent
                    input_box = WebDriverWait(driver, 20).until(
                        EC.element_to_be_clickable((By.CSS_SELECTOR, config["input_selector"]))
                    )
                    input_box.click()
                    
                    # Type Prompt
                    type_like_human(input_box, prompt)
                    random_sleep(0.5, 1.5)

                    # Submit
                    if config.get("enter_key", True):
                        input_box.send_keys(Keys.ENTER)
                    else:
                        submit_btn = driver.find_element(By.CSS_SELECTOR, config["submit_selector"])
                        submit_btn.click()

                    # Wait for Response (Simulate reading time)
                    wait_time = random.randint(15, 30)
                    print(f"      ⏳ Waiting {wait_time}s for response/reading...")
                    time.sleep(wait_time)

                except Exception as e:
                    print(f"⚠️ Error in turn {i+1}: {e}")
                    time.sleep(5)
            
            # End of Scenario Delay
            inter_scenario_wait = random.randint(5, 10)
            print(f"✅ Scenario '{category}' complete. Next scenario in {inter_scenario_wait}s...")
            time.sleep(inter_scenario_wait)
            
            # Move to next scenario, loop back to 0 if at end
            scenario_index = (scenario_index + 1) % len(scenarios)

    except KeyboardInterrupt:
        print("\n🛑 Bot stopped by user.")
    except Exception as e:
        print(f"❌ Fatal Error: {e}")
    finally:
        print("👋 Closing browser...")
        driver.quit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run LLM traffic generation bot (Chrome)")
    parser.add_argument("--target", required=True, choices=LLM_CONFIG.keys(), help="Target LLM provider")
    parser.add_argument("--prompts", default="prompt_bank.json", help="Path to JSON file containing prompt chains")
    
    args = parser.parse_args()

    run_bot(args.target, args.prompts)