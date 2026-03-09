import time
import random
import argparse
import json
import sys
import os
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILE_PATH = os.path.join(SCRIPT_DIR, "chrome_profile")
PROMPT_BANK_PATH = os.path.join(SCRIPT_DIR, "prompt_bank.json")

def load_prompt_chains():
    with open(PROMPT_BANK_PATH, "r") as f:
        chains = json.load(f)
    random.shuffle(chains)
    return chains

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

def dismiss_chatgpt_overlays(driver):
    """Dismiss any modal overlays or popups that might block interaction."""
    try:
        overlays = driver.find_elements(By.CSS_SELECTOR, "div[data-state='open'].fixed.inset-0.z-50")
        for overlay in overlays:
            # Try pressing Escape to dismiss
            driver.find_element(By.TAG_NAME, "body").send_keys(Keys.ESCAPE)
            time.sleep(1)
            break
    except:
        pass
    # Also try dismissing common ChatGPT dialogs/buttons
    for selector in ["button[aria-label='Close']", "div[role='dialog'] button"]:
        try:
            btns = driver.find_elements(By.CSS_SELECTOR, selector)
            for btn in btns:
                if btn.is_displayed():
                    btn.click()
                    time.sleep(0.5)
                    break
        except:
            pass

def wait_for_chatgpt_response(driver, timeout=120):
    """Wait for ChatGPT to finish generating using UI indicators."""
    # Wait for the stop button to appear (response started)
    print("   ⏳ Waiting for response to start...")
    try:
        WebDriverWait(driver, 60).until(
            lambda d: d.find_elements(By.CSS_SELECTOR, "button[data-testid='stop-button'], button[aria-label='Stop streaming']")
        )
    except:
        # Fallback: check if body text grew
        print("   ⚠️  Stop button not found, using text-length fallback.")

    # Wait for the stop button to disappear (response finished)
    print("   ⏳ Response streaming...")
    try:
        WebDriverWait(driver, timeout).until_not(
            lambda d: d.find_elements(By.CSS_SELECTOR, "button[data-testid='stop-button'], button[aria-label='Stop streaming']")
        )
    except:
        print("   ⚠️  Response timed out. Moving on.")

    # Also wait for send button to reappear as confirmation
    try:
        WebDriverWait(driver, 10).until(
            lambda d: d.find_elements(By.CSS_SELECTOR, "button[data-testid='send-button']")
        )
    except:
        pass
    time.sleep(2)

def wait_for_gemini_response(driver, timeout=120):
    """Wait for Gemini to finish generating using text stabilization."""
    initial_len = len(driver.find_element(By.TAG_NAME, "body").text)

    # Wait for response to start (body text grows)
    print("   ⏳ Waiting for response to start...")
    try:
        WebDriverWait(driver, 60).until(
            lambda d: len(d.find_element(By.TAG_NAME, "body").text) > initial_len + 20
        )
    except:
        print("   ⚠️  No response detected. Skipping.")
        return

    # Wait for text to stabilize (streaming finished)
    print("   ⏳ Response streaming...")
    last_len = 0
    stable_count = 0
    deadline = time.time() + timeout
    while time.time() < deadline:
        current_len = len(driver.find_element(By.TAG_NAME, "body").text)
        if current_len == last_len:
            stable_count += 1
            if stable_count >= 6:  # Stable for ~6 seconds
                break
        else:
            stable_count = 0
        last_len = current_len
        time.sleep(1)
    if time.time() >= deadline:
        print("   ⚠️  Response timed out. Moving on.")
    time.sleep(2)

def wait_for_claude_response(driver, timeout=120):
    """Wait for Claude to finish generating using stop button + text stabilization."""
    STOP_SELECTORS = [
        "button[aria-label='Stop Response']",
        "button[aria-label='Stop response']",
        "button[aria-label='Stop']",
        "button.stop-button",
    ]

    initial_len = len(driver.find_element(By.TAG_NAME, "body").text)

    # Try to detect streaming start via stop button
    print("   ⏳ Waiting for response to start...")
    stop_found = False
    try:
        WebDriverWait(driver, 30).until(
            lambda d: any(d.find_elements(By.CSS_SELECTOR, sel) for sel in STOP_SELECTORS)
        )
        stop_found = True
    except:
        # Fallback: check if body text grew
        try:
            WebDriverWait(driver, 30).until(
                lambda d: len(d.find_element(By.TAG_NAME, "body").text) > initial_len + 20
            )
        except:
            print("   ⚠️  No response detected. Skipping.")
            return

    print("   ⏳ Response streaming...")
    if stop_found:
        # Wait for stop button to disappear
        try:
            WebDriverWait(driver, timeout).until_not(
                lambda d: any(d.find_elements(By.CSS_SELECTOR, sel) for sel in STOP_SELECTORS)
            )
        except:
            print("   ⚠️  Response timed out. Moving on.")
    else:
        # Text stabilization fallback
        last_len = 0
        stable_count = 0
        deadline = time.time() + timeout
        while time.time() < deadline:
            current_len = len(driver.find_element(By.TAG_NAME, "body").text)
            if current_len == last_len:
                stable_count += 1
                if stable_count >= 6:
                    break
            else:
                stable_count = 0
            last_len = current_len
            time.sleep(1)
        if time.time() >= deadline:
            print("   ⚠️  Response timed out. Moving on.")
    time.sleep(2)

def open_new_tab(driver, url):
    """Open a new tab, close the old one, and navigate to url for a fresh conversation."""
    try:
        old_handles = set(driver.window_handles)
        old_handle = driver.current_window_handle
        driver.execute_script("window.open('');")
        # Wait for the new tab handle to appear
        WebDriverWait(driver, 10).until(
            lambda d: len(d.window_handles) > len(old_handles)
        )
        new_handle = (set(driver.window_handles) - old_handles).pop()
        driver.switch_to.window(new_handle)
        # Close old tab
        driver.switch_to.window(old_handle)
        driver.close()
        driver.switch_to.window(new_handle)
        driver.get(url)
    except Exception:
        # Fallback: just navigate directly (new conversation via URL)
        driver.get(url)
    time.sleep(5)

def run_chatgpt(driver):
    print("🤖 Mode: ChatGPT")
    chains = load_prompt_chains()

    driver.get("https://chatgpt.com")
    time.sleep(5)
    wait_for_login(driver, "ChatGPT")

    for chain_idx, chain in enumerate(chains, 1):
        prompts = chain["prompts"]
        category = chain.get("category", "unknown")
        print(f"\n{'='*50}")
        print(f"📎 Chain {chain_idx}/{len(chains)}: \"{category}\" ({len(prompts)} prompts)")
        print(f"{'='*50}")

        # Open a new tab for each chain (new conversation)
        if chain_idx > 1:
            open_new_tab(driver, "https://chatgpt.com")

        for i, prompt in enumerate(prompts, 1):
            print(f"\n[ChatGPT {chain_idx}.{i}] Asking: {prompt}")

            dismiss_chatgpt_overlays(driver)

            try:
                input_box = WebDriverWait(driver, 15).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, "#prompt-textarea"))
                )
                input_box.click()
            except:
                dismiss_chatgpt_overlays(driver)
                try:
                    input_box = driver.find_element(By.CSS_SELECTOR, "#prompt-textarea")
                    driver.execute_script("arguments[0].click();", input_box)
                except:
                    input_box = driver.find_element(By.TAG_NAME, "textarea")
                    driver.execute_script("arguments[0].click();", input_box)

            type_human_like(input_box, prompt)
            time.sleep(random.uniform(0.5, 1.5))

            try:
                send_btn = driver.find_element(By.CSS_SELECTOR, "button[data-testid='send-button']")
                send_btn.click()
            except:
                input_box.send_keys(Keys.ENTER)

            wait_for_chatgpt_response(driver)
            print(f"   ✅ Response received.")
            time.sleep(random.uniform(2, 5))

def run_gemini(driver):
    print("🤖 Mode: Gemini")
    chains = load_prompt_chains()

    driver.get("https://gemini.google.com/app")
    time.sleep(5)
    wait_for_login(driver, "Gemini")

    for chain_idx, chain in enumerate(chains, 1):
        prompts = chain["prompts"]
        category = chain.get("category", "unknown")
        print(f"\n{'='*50}")
        print(f"📎 Chain {chain_idx}/{len(chains)}: \"{category}\" ({len(prompts)} prompts)")
        print(f"{'='*50}")

        if chain_idx > 1:
            open_new_tab(driver, "https://gemini.google.com/app")

        for i, prompt in enumerate(prompts, 1):
            print(f"\n[Gemini {chain_idx}.{i}] Asking: {prompt}")

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

            wait_for_gemini_response(driver)
            print(f"   ✅ Response received.")

def run_claude(driver):
    print("🤖 Mode: Claude")
    chains = load_prompt_chains()

    driver.get("https://claude.ai/chats")
    time.sleep(5)
    wait_for_login(driver, "Claude")

    for chain_idx, chain in enumerate(chains, 1):
        prompts = chain["prompts"]
        category = chain.get("category", "unknown")
        print(f"\n{'='*50}")
        print(f"📎 Chain {chain_idx}/{len(chains)}: \"{category}\" ({len(prompts)} prompts)")
        print(f"{'='*50}")

        if chain_idx > 1:
            open_new_tab(driver, "https://claude.ai/chats")

        for i, prompt in enumerate(prompts, 1):
            print(f"\n[Claude {chain_idx}.{i}] Asking: {prompt}")

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

            wait_for_claude_response(driver)
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