import time
import random
import argparse
import sys
import os
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# --- CONFIGURATION ---
PROFILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chrome_profile")
NUM_QUERIES = 5

PROMPTS = [
    "Explain the TCP 3-way handshake.",
    "Difference between SSL and TLS?",
    "How does a buffer overflow work?",
    "Explain packet switching.",
    "What are the 7 layers of the OSI model?"
]

def launch_browser():
    print(f"🌐 Launching Chrome (undetected)...")
    print(f"   Profile: {PROFILE_PATH}")
    os.makedirs(PROFILE_PATH, exist_ok=True)

    options = uc.ChromeOptions()
    options.add_argument(f"--user-data-dir={PROFILE_PATH}")

    # Enable TLS key logging for packet decryption
    sslkeylog_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "sslkeylogfile.txt")
    os.makedirs(os.path.dirname(sslkeylog_path), exist_ok=True)
    options.add_argument(f"--ssl-key-log-file={sslkeylog_path}")

    try:
        driver = uc.Chrome(options=options, version_main=145)
        print(f"✅ Launched!")
        return driver
    except Exception as e:
        print(f"❌ Error launching Chrome.")
        print(f"1. Make sure Google Chrome is installed.")
        print(f"2. Make sure you CLOSED all Chrome windows.")
        print(f"Details: {e}")
        sys.exit(1)

def type_human_like(element, text):
    for char in text:
        element.send_keys(char)
        time.sleep(random.uniform(0.05, 0.15))

def wait_for_login(driver, site_name):
    """Pause and let the user log in manually before proceeding."""
    input(f"\n🔑 Log in to {site_name} in the browser, then press ENTER here to continue...")
    print("   ✅ Continuing!")
    time.sleep(2)

def wait_for_chatgpt_response(driver, timeout=120):
    """Wait for ChatGPT to finish generating by watching page content changes."""
    # Snapshot the page text length before the response
    initial_len = len(driver.find_element(By.TAG_NAME, "body").text)

    # Wait for page content to grow (response started)
    print("   ⏳ Waiting for response to start...")
    try:
        WebDriverWait(driver, 60).until(
            lambda d: len(d.find_element(By.TAG_NAME, "body").text) > initial_len + 20
        )
    except:
        print("   ⚠️  No response detected. Skipping.")
        return

    # Wait for content to stop changing (streaming finished)
    print("   ⏳ Response streaming...")
    last_len = 0
    stable_count = 0
    deadline = time.time() + timeout
    while time.time() < deadline:
        current_len = len(driver.find_element(By.TAG_NAME, "body").text)
        if current_len == last_len:
            stable_count += 1
            if stable_count >= 4:  # Stable for ~4 seconds
                break
        else:
            stable_count = 0
        last_len = current_len
        time.sleep(1)
    if time.time() >= deadline:
        print("   ⚠️  Response timed out. Moving on.")
    time.sleep(2)

def run_chatgpt(driver):
    print("🤖 Mode: ChatGPT")
    if "chatgpt.com" not in driver.current_url:
        driver.get("https://chatgpt.com")
        time.sleep(5)


    # Wait for login
    wait_for_login(driver, "ChatGPT")

    for i, prompt in enumerate(PROMPTS[:NUM_QUERIES], 1):
        print(f"\n[ChatGPT {i}] Asking: {prompt}")
        
        try:
            input_box = WebDriverWait(driver, 15).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "#prompt-textarea"))
            )
        except:
            input_box = driver.find_element(By.TAG_NAME, "textarea")

        input_box.click()
        type_human_like(input_box, prompt)
        time.sleep(random.uniform(0.5, 1.5))

        try:
            send_btn = driver.find_element(By.CSS_SELECTOR, "button[data-testid='send-button']")
            send_btn.click()
        except:
            input_box.send_keys(Keys.ENTER)

        wait_for_chatgpt_response(driver)
        print(f"   ✅ Response received.")
        time.sleep(random.uniform(2, 5))  # Human-like pause between queries

def run_gemini(driver):
    print("🤖 Mode: Gemini")
    if "gemini.google.com" not in driver.current_url:
        driver.get("https://gemini.google.com/app")
        time.sleep(5)


    wait_for_login(driver, "Gemini")

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

        print("   ⏳ Waiting for response...")
        try:
            WebDriverWait(driver, 120).until(
                lambda d: d.find_elements(By.CSS_SELECTOR, "model-response, .model-response-text")
                and not d.find_elements(By.CSS_SELECTOR, ".loading, .thinking-indicator")
            )
        except:
            pass
        time.sleep(3)
        print(f"   ✅ Response received.")

def run_claude(driver):
    print("🤖 Mode: Claude")
    if "claude.ai" not in driver.current_url:
        driver.get("https://claude.ai/chats")
        time.sleep(5)


    wait_for_login(driver, "Claude")

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

        print("   ⏳ Waiting for response...")
        try:
            WebDriverWait(driver, 30).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "button[aria-label='Stop Response']"))
            )
        except:
            pass
        try:
            WebDriverWait(driver, 120).until_not(
                EC.presence_of_element_located((By.CSS_SELECTOR, "button[aria-label='Stop Response']"))
            )
        except:
            pass
        time.sleep(2)
        print(f"   ✅ Response received.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["chatgpt", "gemini", "claude"], required=True)
    args = parser.parse_args()

    # Verify Chrome exists
    if not os.path.exists("/Applications/Google Chrome.app"):
        print("\u274c CRITICAL ERROR: Google Chrome not found at /Applications/Google Chrome.app")
        sys.exit(1)

    driver = launch_browser()

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
        print("👋 Closing Chrome.")
        driver.quit()