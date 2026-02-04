import time
import random
import argparse
import sys
import os
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.firefox import GeckoDriverManager

# --- CONFIGURATION ---
# UPDATE THIS to your actual Firefox path if different
FIREFOX_BINARY_PATH = r"C:\Program Files\Mozilla Firefox\firefox.exe"
PROFILE_PATH = r"C:\Users\matth\Downloads\selenium\FirefoxProfile"
NUM_QUERIES = 5

PROMPTS = [
    "Explain the TCP 3-way handshake.",
    "Difference between SSL and TLS?",
    "How does a buffer overflow work?",
    "Explain packet switching.",
    "What are the 7 layers of the OSI model?"
]

def launch_firefox_stealth():
    print(f"🦊 Launching Firefox...")
    print(f"   Profile: {PROFILE_PATH}")
    print(f"   Binary:  {FIREFOX_BINARY_PATH}")
    
    # 1. Ensure Sniffing is Active
    os.environ["SSLKEYLOGFILE"] = os.path.join(os.getcwd(), "data/sslkeylogfile.txt")

    options = Options()
    # ⚠️ FIX: Explicitly tell Selenium where Firefox is
    options.binary_location = FIREFOX_BINARY_PATH
    
    options.add_argument("-profile")
    options.add_argument(PROFILE_PATH)

    # Stealth Switches
    options.set_preference("dom.webdriver.enabled", False)
    options.set_preference("useAutomationExtension", False)

    try:
        service = Service(GeckoDriverManager().install())
        driver = webdriver.Firefox(service=service, options=options)
        print(f"✅ Launched! Title: {driver.title}")
        return driver
    except Exception as e:
        print(f"❌ Error launching Firefox.")
        print(f"1. Check if '{FIREFOX_BINARY_PATH}' exists.")
        print(f"2. Make sure you CLOSED the manual Firefox window.")
        print(f"Details: {e}")
        sys.exit(1)

def type_human_like(element, text):
    for char in text:
        element.send_keys(char)
        time.sleep(random.uniform(0.05, 0.15))

def run_chatgpt(driver):
    print("🤖 Mode: ChatGPT")
    if "chatgpt.com" not in driver.current_url:
        driver.get("https://chatgpt.com")
        time.sleep(5)

    for i, prompt in enumerate(PROMPTS[:NUM_QUERIES], 1):
        print(f"\n[ChatGPT {i}] Asking: {prompt}")
        
        try:
            # Wait longer for initial load
            input_box = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "#prompt-textarea"))
            )
        except:
            input_box = driver.find_element(By.TAG_NAME, "textarea")

        input_box.click()
        type_human_like(input_box, prompt)
        time.sleep(0.5)

        try:
            send_btn = driver.find_element(By.CSS_SELECTOR, "button[data-testid='send-button']")
            send_btn.click()
        except:
            input_box.send_keys(Keys.ENTER)

        print("⏳ Waiting 15s...")
        time.sleep(15)

def run_gemini(driver):
    print("🤖 Mode: Gemini")
    if "gemini.google.com" not in driver.current_url:
        driver.get("https://gemini.google.com/app")
        time.sleep(5)

    for i, prompt in enumerate(PROMPTS[:NUM_QUERIES], 1):
        print(f"\n[Gemini {i}] Asking: {prompt}")
        
        try:
            input_box = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "div[contenteditable='true']"))
            )
            input_box.click() 
        except:
            print("❌ Input not found. Are you logged in?")
            break

        type_human_like(input_box, prompt)
        time.sleep(1)
        input_box.send_keys(Keys.ENTER)
        print("⏳ Waiting 15s...")
        time.sleep(15)

def run_claude(driver):
    print("🤖 Mode: Claude")
    if "claude.ai" not in driver.current_url:
        driver.get("https://claude.ai/chats")
        time.sleep(5)

    for i, prompt in enumerate(PROMPTS[:NUM_QUERIES], 1):
        print(f"\n[Claude {i}] Asking: {prompt}")
        
        try:
            input_box = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "div[contenteditable='true']"))
            )
            input_box.click()
        except:
            print("❌ Input not found. Are you logged in?")
            break

        type_human_like(input_box, prompt)
        time.sleep(0.5)
        input_box.send_keys(Keys.ENTER)
        print("⏳ Waiting 15s...")
        time.sleep(15)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["chatgpt", "gemini", "claude"], required=True)
    args = parser.parse_args()

    # Verify path exists before running
    if not os.path.exists(FIREFOX_BINARY_PATH):
        print(f"❌ CRITICAL ERROR: Could not find Firefox at: {FIREFOX_BINARY_PATH}")
        print("Please check where your firefox.exe is installed and update the script.")
        sys.exit(1)

    driver = launch_firefox_stealth()

    try:
        if args.target == "chatgpt":
            run_chatgpt(driver)
        elif args.target == "gemini":
            run_gemini(driver)
        elif args.target == "claude":
            run_claude(driver)
    except KeyboardInterrupt:
        print("\n🛑 Stopped.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        print("👋 Closing Firefox.")
        driver.quit()