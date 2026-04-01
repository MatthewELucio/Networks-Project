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

# --- PATH & ENV CONFIGURATION ---
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent.parent.parent
env_path = project_root / ".env"
load_dotenv(dotenv_path=env_path, override=True)

# Standardized Config: If a selector fails, you can manually click/type
LLM_CONFIG = {
    "chatgpt": {
        "url": "https://chatgpt.com",
        "input_selector": "#prompt-textarea",
        "submit_selector": "button[data-testid='send-button']",
    },
    "claude": {
        "url": "https://claude.ai",
        "input_selector": "div[contenteditable='true']",
        "submit_selector": "button[aria-label*='Send Message']", 
    },
    "gemini": {
        "url": "https://gemini.google.com",
        "input_selector": "div[role='textbox']",
        "submit_selector": "button[aria-label='Send message']",
    }
}

# --- WINDOWS HANDLE PATCH ---
def _suppress_win_error(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except OSError as e:
            if e.errno == 6: pass
            else: raise
    return wrapper

uc.Chrome.quit = _suppress_win_error(uc.Chrome.quit)

# --- HELPER FUNCTIONS ---

def get_chrome_main_version():
    """Finds local Chrome version to prevent SessionNotCreatedException."""
    try:
        if sys.platform == "win32":
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Google\Chrome\BLBeacon")
            v, _ = winreg.QueryValueEx(key, "version")
            return int(v.split('.')[0])
    except:
        return None 

def type_safely(element, text):
    """Prevents cursor jumping by using Select-All + Paste logic."""
    try:
        element.click()
        time.sleep(0.5)
        # Standard 'Select All' then 'Delete'
        element.send_keys(Keys.CONTROL + "a")
        element.send_keys(Keys.BACKSPACE)
        time.sleep(0.3)
        # Send the whole prompt block
        element.send_keys(text)
        time.sleep(1.0)
    except Exception as e:
        print(f"⚠️ Typing Error: {e}")

def get_driver():
    version = get_chrome_main_version()
    print(f"🚀 Launching Undetected Chrome (Version: {version})...")
    options = uc.ChromeOptions()
    driver = uc.Chrome(options=options, use_subprocess=True, version_main=version)
    return driver

def run_bot(target_name, prompt_bank_path):
    if target_name not in LLM_CONFIG:
        print(f"❌ Unknown target: {target_name}")
        return

    with open(prompt_bank_path, 'r', encoding='utf-8') as f:
        scenarios = json.load(f)
    
    random.shuffle(scenarios)
    config = LLM_CONFIG[target_name]
    driver = get_driver()

    try:
        print(f"🌐 Navigating to {target_name.upper()}...")
        driver.get(config["url"])

        print("\n" + "="*60)
        print(f"⚠️  ACTION REQUIRED: Please LOG IN to {target_name.upper()} manually.")
        print("👉  Dismiss any pop-ups and press ENTER in this terminal once ready...")
        print("="*60 + "\n")
        input()

        while True:
            scenario = random.choice(scenarios)
            prompts = scenario.get("prompts", [])
            print(f"\n🎭 Scenario: '{scenario.get('category')}'")

            for i, prompt in enumerate(prompts):
                print(f"  ➡ Turn {i+1}/{len(prompts)}: {prompt[:50]}...")

                try:
                    # Find Input Box
                    input_box = WebDriverWait(driver, 15).until(
                        EC.element_to_be_clickable((By.CSS_SELECTOR, config["input_selector"]))
                    )
                    
                    type_safely(input_box, prompt)
                    
                    # Small wait for button to become active
                    time.sleep(3)
                    
                    # 4. Submit logic
                    # if target_name == "claude":
                        # Try hitting Enter if the button is missing
                    input_box.send_keys(Keys.ENTER)
                    # else:
                    #     submit_btn = driver.find_element(By.CSS_SELECTOR, config["submit_selector"])
                    #     submit_btn.click()

                    # Wait for Response
                    wait_time = random.randint(30, 40)
                    print(f"    ⏳ Waiting {wait_time}s for response...")
                    time.sleep(wait_time)

                except Exception as e:
                    print(f"⚠️ Turn failed: {e}")
                    print("👉 If a pop-up is blocking, close it manually. Retrying in 5s...")
                    time.sleep(5)
            
            print(f"✅ Scenario complete.")
            time.sleep(random.randint(5, 15))

    except KeyboardInterrupt:
        print("\n🛑 Stopped by user.")
    finally:
        driver.quit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, choices=LLM_CONFIG.keys())
    parser.add_argument("--prompts", default="prompt_bank.json")
    args = parser.parse_args()

    run_bot(args.target, args.prompts)