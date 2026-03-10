import time
import random
import argparse
import json
import sys
import os
import glob
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILE_PATH = os.path.join(SCRIPT_DIR, "chrome_profile")
PROMPT_BANK_PATH = os.path.join(SCRIPT_DIR, "prompt_bank.json")
SAMPLE_PDFS_DIR = os.path.join(SCRIPT_DIR, "sample_pdfs")

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

def get_prompt_text(prompt_item):
    """Extract the text from a prompt entry (plain string or {text, attachment} object)."""
    if isinstance(prompt_item, dict):
        return prompt_item.get("text", "")
    return prompt_item

def get_prompt_attachment(prompt_item):
    """Return the attachment type if present, else None."""
    if isinstance(prompt_item, dict):
        return prompt_item.get("attachment")
    return None

def pick_random_pdf():
    """Return the absolute path to a random PDF from the sample_pdfs directory."""
    pdfs = glob.glob(os.path.join(SAMPLE_PDFS_DIR, "*.pdf"))
    if not pdfs:
        print("   ⚠️  No PDFs found in sample_pdfs/. Skipping upload.")
        return None
    return random.choice(pdfs)

def upload_file_to_llm(driver, file_path, target="chatgpt"):
    """Upload a file to an LLM chat service.

    Each service hides the <input type='file'> and only creates/activates it
    when the user clicks an attachment button.  This function clicks the
    appropriate button first, then sends the file path to the revealed input.
    """
    try:
        if target == "chatgpt":
            _upload_chatgpt(driver, file_path)
        elif target == "gemini":
            _upload_gemini(driver, file_path)
        elif target == "claude":
            _upload_claude(driver, file_path)
        else:
            _upload_generic(driver, file_path)
    except Exception as e:
        print(f"   ⚠️  File upload failed: {e}")


def _send_file_to_input(driver, file_path):
    """Find the visible/active <input type='file'> and send the file path."""
    file_inputs = driver.find_elements(By.CSS_SELECTOR, "input[type='file']")
    if not file_inputs:
        raise RuntimeError("No <input type='file'> found on page")
    # Make all inputs interactable and use the last one (closest to chat area)
    for fi in file_inputs:
        driver.execute_script(
            "arguments[0].style.display = 'block';"
            "arguments[0].style.visibility = 'visible';"
            "arguments[0].style.opacity = '1';"
            "arguments[0].style.position = 'absolute';"
            "arguments[0].style.height = '1px';"
            "arguments[0].style.width = '1px';",
            fi,
        )
    file_inputs[-1].send_keys(file_path)


def _upload_chatgpt(driver, file_path):
    """ChatGPT: click the attachment button, then send file to the input."""
    # ChatGPT has a paperclip / "Attach files" button in the composer
    attach_selectors = [
        "button[aria-label='Attach files']",
        "button[aria-label='Attach file']",
        "button[data-testid='composer-attach-button']",
        "button[aria-label='Upload file']",
    ]
    clicked = False
    for sel in attach_selectors:
        btns = driver.find_elements(By.CSS_SELECTOR, sel)
        for btn in btns:
            if btn.is_displayed():
                btn.click()
                clicked = True
                break
        if clicked:
            break

    time.sleep(1)

    # After clicking attach, a file input should now be active
    _send_file_to_input(driver, file_path)
    print(f"   📎 Uploading: {os.path.basename(file_path)}")

    # Wait for file chip / attachment badge to appear
    _wait_for_upload_confirmation(driver, "chatgpt")
    print(f"   📎 Upload confirmed.")


def _upload_gemini(driver, file_path):
    """Gemini: click the '+' add-content button, then the upload option."""
    # Gemini has a '+' button at the bottom-left of the input area
    add_selectors = [
        "button[aria-label='Add content']",
        "button[aria-label='Add']",
        "button[aria-label='More options']",
        "button[mattooltip='Add']",
    ]
    clicked = False
    for sel in add_selectors:
        btns = driver.find_elements(By.CSS_SELECTOR, sel)
        for btn in btns:
            if btn.is_displayed():
                btn.click()
                clicked = True
                break
        if clicked:
            break

    # If button selectors failed, try the "+" icon by XPath text content
    if not clicked:
        try:
            plus_btns = driver.find_elements(By.XPATH,
                "//button[contains(@class, 'add') or .//mat-icon[text()='add'] or .//span[text()='+']]"
            )
            for btn in plus_btns:
                if btn.is_displayed():
                    btn.click()
                    clicked = True
                    break
        except:
            pass

    time.sleep(1)

    # After the menu opens, look for an "Upload file" menu item and click it
    upload_menu_selectors = [
        "button[aria-label='Upload file']",
        "div[role='menuitem'][aria-label='Upload file']",
        "span[class*='upload']",
    ]
    for sel in upload_menu_selectors:
        items = driver.find_elements(By.CSS_SELECTOR, sel)
        for item in items:
            if item.is_displayed():
                item.click()
                time.sleep(1)
                break

    # Now send the file to the input
    _send_file_to_input(driver, file_path)
    print(f"   📎 Uploading: {os.path.basename(file_path)}")

    _wait_for_upload_confirmation(driver, "gemini")
    print(f"   📎 Upload confirmed.")


def _upload_claude(driver, file_path):
    """Claude: click the paperclip button, then send file to the input."""
    attach_selectors = [
        "button[aria-label='Attach files']",
        "button[aria-label='Attach file']",
        "button[aria-label='Upload file']",
        "button[data-testid='file-upload']",
    ]
    clicked = False
    for sel in attach_selectors:
        btns = driver.find_elements(By.CSS_SELECTOR, sel)
        for btn in btns:
            if btn.is_displayed():
                btn.click()
                clicked = True
                break
        if clicked:
            break

    time.sleep(1)

    _send_file_to_input(driver, file_path)
    print(f"   📎 Uploading: {os.path.basename(file_path)}")

    _wait_for_upload_confirmation(driver, "claude")
    print(f"   📎 Upload confirmed.")


def _upload_generic(driver, file_path):
    """Fallback: just try sending file to any file input on the page."""
    _send_file_to_input(driver, file_path)
    print(f"   📎 Uploading: {os.path.basename(file_path)}")
    time.sleep(5)
    print(f"   📎 Upload assumed complete (generic fallback).")


def _wait_for_upload_confirmation(driver, target, timeout=20):
    """Wait until the UI shows the uploaded file (chip, badge, or text change)."""
    # Capture initial page state to detect changes
    initial_len = len(driver.find_element(By.TAG_NAME, "body").text)

    try:
        # Wait for any visible change in the composer area (file chips, badges, etc.)
        WebDriverWait(driver, timeout).until(
            lambda d: len(d.find_element(By.TAG_NAME, "body").text) > initial_len + 5
            or d.find_elements(By.CSS_SELECTOR,
                "div[class*='attachment'], button[aria-label*='Remove'], "
                "div[data-testid*='file'], div[class*='chip'], "
                "div[class*='upload'], img[alt*='Uploaded']"
            )
        )
    except:
        # Fallback: just wait a fixed period
        print("   ⚠️  Could not confirm upload via UI indicator, waiting 5s...")
        time.sleep(5)

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

        # Skip document analysis chains on ChatGPT
        if category == "document analysis":
            print(f"\n⏭️  Skipping chain {chain_idx}/{len(chains)}: \"{category}\" (not supported on ChatGPT)")
            continue

        print(f"\n{'='*50}")
        print(f"📎 Chain {chain_idx}/{len(chains)}: \"{category}\" ({len(prompts)} prompts)")
        print(f"{'='*50}")

        # Open a new tab for each chain (new conversation)
        if chain_idx > 1:
            open_new_tab(driver, "https://chatgpt.com")

        for i, prompt_item in enumerate(prompts, 1):
            prompt_text = get_prompt_text(prompt_item)
            attachment = get_prompt_attachment(prompt_item)
            print(f"\n[ChatGPT {chain_idx}.{i}] Asking: {prompt_text}")

            dismiss_chatgpt_overlays(driver)

            # Upload PDF if this prompt has an attachment
            if attachment == "pdf":
                pdf_path = pick_random_pdf()
                if pdf_path:
                    upload_file_to_llm(driver, pdf_path, target="chatgpt")

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

            type_human_like(input_box, prompt_text)
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

        for i, prompt_item in enumerate(prompts, 1):
            prompt_text = get_prompt_text(prompt_item)
            attachment = get_prompt_attachment(prompt_item)
            print(f"\n[Gemini {chain_idx}.{i}] Asking: {prompt_text}")

            # Upload PDF if this prompt has an attachment
            if attachment == "pdf":
                pdf_path = pick_random_pdf()
                if pdf_path:
                    upload_file_to_llm(driver, pdf_path, target="gemini")

            try:
                input_box = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "div[contenteditable='true']"))
                )
                input_box.click()
            except:
                print("❌ Input not found. Are you logged in?")
                break

            type_human_like(input_box, prompt_text)
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

        for i, prompt_item in enumerate(prompts, 1):
            prompt_text = get_prompt_text(prompt_item)
            attachment = get_prompt_attachment(prompt_item)
            print(f"\n[Claude {chain_idx}.{i}] Asking: {prompt_text}")

            # Upload PDF if this prompt has an attachment
            if attachment == "pdf":
                pdf_path = pick_random_pdf()
                if pdf_path:
                    upload_file_to_llm(driver, pdf_path, target="claude")

            try:
                input_box = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "div[contenteditable='true']"))
                )
                input_box.click()
            except:
                print("❌ Input not found. Are you logged in?")
                break

            type_human_like(input_box, prompt_text)
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