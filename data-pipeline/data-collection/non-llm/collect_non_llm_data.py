"""
collect_non_llm_data.py

Automated browser-based collection of non-LLM web traffic for fingerprinting research.
Visits top sites with realistic human-like interactions using undetected_chromedriver.
Run packet capture (tcpdump/tshark) separately — this script just drives the browser.

Usage:
    python collect_non_llm_data.py --browser chrome
    python collect_non_llm_data.py --browser firefox
    python collect_non_llm_data.py --browser chrome --num-sites 50
    python collect_non_llm_data.py --browser firefox --num-sites 20 --actions-per-site 8

Dependencies:
    - undetected_chromedriver (for chrome)
    - selenium
    - geckodriver (for firefox)
"""

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
from urllib.parse import urlparse

# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CHROME_PROFILE_PATH = os.path.join(SCRIPT_DIR, "chrome_profile_nonllm")
FIREFOX_PROFILE_PATH = os.path.join(SCRIPT_DIR, "firefox_profile_nonllm")

# Top 100 sites (diverse categories: search, social, news, shopping, entertainment, etc.)
TOP_SITES = [
    "google.com", "youtube.com", "facebook.com", "instagram.com", "x.com",
    "wikipedia.org", "reddit.com", "yahoo.com", "amazon.com", "linkedin.com",
    "netflix.com", "bing.com", "twitch.tv", "microsoft.com", "apple.com",
    "pinterest.com", "espn.com", "cnn.com", "nytimes.com", "bbc.com",
    "weather.com", "imdb.com", "craigslist.org", "ebay.com", "walmart.com",
    "target.com", "bestbuy.com", "etsy.com", "zillow.com", "yelp.com",
    "stackoverflow.com", "github.com", "medium.com", "quora.com", "tumblr.com",
    "flickr.com", "vimeo.com", "soundcloud.com", "spotify.com", "pandora.com",
    "hulu.com", "disneyplus.com", "hbomax.com", "peacocktv.com", "paramountplus.com",
    "washingtonpost.com", "usatoday.com", "foxnews.com", "nbcnews.com", "abcnews.go.com",
    "reuters.com", "apnews.com", "theguardian.com", "forbes.com", "businessinsider.com",
    "cnbc.com", "bloomberg.com", "wsj.com", "techcrunch.com", "wired.com",
    "arstechnica.com", "theverge.com", "engadget.com", "mashable.com", "gizmodo.com",
    "booking.com", "airbnb.com", "tripadvisor.com", "expedia.com", "kayak.com",
    "webmd.com", "mayoclinic.org", "healthline.com", "nih.gov", "cdc.gov",
    "nasa.gov", "whitehouse.gov", "irs.gov", "usps.com", "ups.com",
    "fedex.com", "homedepot.com", "lowes.com", "costco.com", "macys.com",
    "nordstrom.com", "nike.com", "adidas.com", "underarmour.com", "gap.com",
    "ikea.com", "wayfair.com", "chewy.com", "gamestop.com", "newegg.com",
    "dropbox.com", "zoom.us", "slack.com", "notion.so", "figma.com",
]

# --- BROWSER LAUNCH ---

def launch_browser(browser="chrome"):
    sslkeylog_path = os.path.join(SCRIPT_DIR, "data", "sslkeylogfile.txt")
    os.makedirs(os.path.dirname(sslkeylog_path), exist_ok=True)

    if browser == "firefox":
        return _launch_firefox(sslkeylog_path)
    else:
        return _launch_chrome(sslkeylog_path)

def _launch_chrome(sslkeylog_path):
    print("🌐 Launching Chrome (undetected)...")

    options = uc.ChromeOptions()
    options.add_argument(f"--ssl-key-log-file={sslkeylog_path}")

    try:
        # No user-data-dir — lets UC create a temp profile so it won't
        # conflict with other Chrome instances (e.g. the LLM bot)
        driver = uc.Chrome(options=options, version_main=145)
        time.sleep(2)
        driver.set_page_load_timeout(30)
        print("✅ Launched!")
        return driver
    except Exception as e:
        print("❌ Error launching Chrome.")
        print("1. Make sure Google Chrome is installed.")
        print(f"Details: {e}")
        sys.exit(1)

def _launch_firefox(sslkeylog_path):
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.firefox.service import Service as FirefoxService
    from selenium import webdriver

    print("🦊 Launching Firefox...")
    print(f"   Profile: {FIREFOX_PROFILE_PATH}")
    os.makedirs(FIREFOX_PROFILE_PATH, exist_ok=True)

    # Set SSLKEYLOGFILE env var for Firefox TLS key logging
    os.environ["SSLKEYLOGFILE"] = sslkeylog_path

    options = FirefoxOptions()
    options.add_argument("-profile")
    options.add_argument(FIREFOX_PROFILE_PATH)

    try:
        driver = webdriver.Firefox(options=options)
        driver.set_page_load_timeout(30)
        print("✅ Launched!")
        return driver
    except Exception as e:
        print("❌ Error launching Firefox.")
        print("1. Make sure Firefox is installed.")
        print("2. Make sure geckodriver is installed (brew install geckodriver).")
        print("3. Make sure you CLOSED all Firefox windows.")
        print(f"Details: {e}")
        sys.exit(1)

# --- HUMAN-LIKE ACTIONS (traffic-heavy) ---

def scroll_page(driver):
    """Scroll the page to trigger lazy-loaded content (images, ads, infinite scroll)."""
    for _ in range(random.randint(2, 5)):
        distance = random.randint(300, 1000)
        driver.execute_script(f"window.scrollBy(0, {distance});")
        time.sleep(random.uniform(0.5, 1.5))
    # Scroll back up partially
    driver.execute_script(f"window.scrollBy(0, -{random.randint(100, 400)});")
    time.sleep(random.uniform(0.5, 1.0))

def click_any_link(driver, base_domain):
    """Click a random visible link — internal or external — to generate navigation traffic."""
    try:
        links = driver.find_elements(By.CSS_SELECTOR, "a[href]")
        visible_links = []
        for link in links:
            try:
                href = link.get_attribute("href") or ""
                if href.startswith("http") and link.is_displayed() and link.size.get("height", 0) > 0:
                    visible_links.append(link)
            except:
                continue
        if not visible_links:
            return False
        chosen = random.choice(visible_links[:30])
        href = chosen.get_attribute("href") or ""
        print(f"      🔗 Navigating: {href[:80]}")
        driver.execute_script("arguments[0].click();", chosen)
        time.sleep(random.uniform(2.0, 5.0))
        # Navigate back if we left the domain
        if base_domain not in driver.current_url:
            driver.back()
            time.sleep(random.uniform(1.5, 3.0))
        return True
    except:
        return False

def click_internal_link(driver, base_domain):
    """Click a random visible internal link on the page."""
    try:
        links = driver.find_elements(By.CSS_SELECTOR, "a[href]")
        visible_links = []
        for link in links:
            try:
                href = link.get_attribute("href") or ""
                parsed = urlparse(href)
                if not parsed.netloc or base_domain in parsed.netloc:
                    if link.is_displayed() and link.size.get("height", 0) > 0:
                        visible_links.append(link)
            except:
                continue
        if not visible_links:
            return False
        chosen = random.choice(visible_links[:20])
        print(f"      🔗 Clicking: {chosen.text[:60] or chosen.get_attribute('href')[:60]}")
        driver.execute_script("arguments[0].click();", chosen)
        time.sleep(random.uniform(2.0, 4.0))
        return True
    except:
        return False

def navigate_subpages(driver, base_domain):
    """Visit multiple subpages on the same site to generate sustained traffic."""
    try:
        links = driver.find_elements(By.CSS_SELECTOR, "a[href]")
        internal = []
        for link in links:
            try:
                href = link.get_attribute("href") or ""
                parsed = urlparse(href)
                if base_domain in (parsed.netloc or "") and href != driver.current_url:
                    internal.append(href)
            except:
                continue
        internal = list(set(internal))
        random.shuffle(internal)
        visited = 0
        for href in internal[:random.randint(2, 4)]:
            print(f"      📄 Subpage: {href[:80]}")
            driver.get(href)
            time.sleep(random.uniform(2.0, 5.0))
            # Scroll to load lazy content
            for _ in range(random.randint(1, 3)):
                driver.execute_script(f"window.scrollBy(0, {random.randint(300, 800)});")
                time.sleep(random.uniform(0.5, 1.5))
            visited += 1
        return visited > 0
    except:
        return False

def interact_with_search(driver):
    """Find and use a search box — triggers autocomplete, suggestions, and results page loads."""
    search_selectors = [
        "input[type='search']",
        "input[name='q']",
        "input[name='query']",
        "input[name='search']",
        "input[placeholder*='earch']",
        "input[aria-label*='earch']",
    ]
    search_terms = [
        "weather today", "best restaurants near me", "how to cook pasta",
        "latest news 2026", "movie reviews new releases", "travel deals europe",
        "python tutorial beginners", "home improvement tips", "fitness workout plan",
        "stock market today", "recipe for chocolate cake", "best laptops 2026",
        "learn guitar online", "history of the internet", "climate change effects",
    ]
    for selector in search_selectors:
        try:
            box = driver.find_element(By.CSS_SELECTOR, selector)
            if box.is_displayed():
                box.click()
                time.sleep(random.uniform(0.3, 0.8))
                term = random.choice(search_terms)
                print(f"      🔍 Searching: {term}")
                # Type character by character (triggers autocomplete requests)
                for char in term:
                    box.send_keys(char)
                    time.sleep(random.uniform(0.04, 0.12))
                time.sleep(random.uniform(1.0, 2.0))
                box.send_keys(Keys.ENTER)
                time.sleep(random.uniform(3.0, 6.0))
                # Click a search result if any
                try:
                    results = driver.find_elements(By.CSS_SELECTOR, "a[href]")
                    clickable = [r for r in results if r.is_displayed() and r.size.get("height", 0) > 10]
                    if clickable:
                        chosen = random.choice(clickable[:10])
                        print(f"      📎 Clicking result: {chosen.text[:50]}")
                        driver.execute_script("arguments[0].click();", chosen)
                        time.sleep(random.uniform(2.0, 4.0))
                        driver.back()
                        time.sleep(random.uniform(1.5, 3.0))
                except:
                    pass
                return True
        except:
            continue
    return False

def load_media_elements(driver):
    """Scroll through the page to force-load images, videos, and iframes."""
    print("      🖼️  Loading media elements...")
    page_height = driver.execute_script("return document.body.scrollHeight")
    viewport = driver.execute_script("return window.innerHeight")
    position = 0
    while position < page_height:
        position += viewport
        driver.execute_script(f"window.scrollTo(0, {position});")
        time.sleep(random.uniform(0.3, 0.8))
    # Click on any video play buttons
    try:
        play_btns = driver.find_elements(By.CSS_SELECTOR,
            "button[aria-label*='lay'], button[class*='play'], [data-testid*='play']")
        for btn in play_btns[:1]:
            if btn.is_displayed():
                print("      ▶️  Playing media...")
                btn.click()
                time.sleep(random.uniform(3.0, 8.0))
                break
    except:
        pass
    time.sleep(random.uniform(0.5, 1.5))

def interact_with_forms(driver):
    """Find and interact with forms (login, newsletter, contact) to trigger POST requests."""
    try:
        inputs = driver.find_elements(By.CSS_SELECTOR,
            "input[type='text'], input[type='email'], input[type='tel']")
        visible = [inp for inp in inputs if inp.is_displayed()]
        if not visible:
            return False
        print("      📝 Interacting with form...")
        for inp in visible[:3]:
            try:
                inp_type = inp.get_attribute("type") or ""
                name = (inp.get_attribute("name") or inp.get_attribute("placeholder") or "").lower()
                if "email" in name or inp_type == "email":
                    inp.send_keys("testuser@example.com")
                elif "name" in name:
                    inp.send_keys("Test User")
                elif "phone" in name or "tel" in name or inp_type == "tel":
                    inp.send_keys("5551234567")
                else:
                    inp.send_keys("test query")
                time.sleep(random.uniform(0.3, 0.8))
            except:
                continue
        # Don't actually submit — just typing triggers validation/autocomplete traffic
        return True
    except:
        return False

def trigger_ajax_content(driver):
    """Click buttons/tabs that load dynamic content via AJAX/fetch."""
    ajax_selectors = [
        "button:not([type='submit'])",
        "[role='tab']",
        "[data-toggle]",
        ".tab, .accordion-header",
        "details > summary",
        "[class*='load-more'], [class*='show-more']",
        "button[class*='more']",
    ]
    try:
        for selector in ajax_selectors:
            elements = driver.find_elements(By.CSS_SELECTOR, selector)
            visible = [e for e in elements if e.is_displayed() and e.size.get("height", 0) > 0]
            if visible:
                chosen = random.choice(visible[:10])
                text = chosen.text[:40] or chosen.get_attribute("aria-label") or "element"
                print(f"      ⚡ Clicking dynamic element: {text}")
                driver.execute_script("arguments[0].click();", chosen)
                time.sleep(random.uniform(1.5, 3.5))
                return True
    except:
        pass
    return False

def back_and_forward(driver):
    """Navigate back and forward to re-trigger page loads."""
    try:
        print("      ↩️  Back/forward navigation...")
        driver.back()
        time.sleep(random.uniform(2.0, 4.0))
        driver.forward()
        time.sleep(random.uniform(2.0, 4.0))
    except:
        pass

def perform_actions(driver, base_domain, num_actions):
    """Perform a series of random actions, heavily weighted toward traffic-generating ones."""
    # Weights: higher number = more likely to be picked
    action_pool = [
        ("click_any",    3, lambda: click_any_link(driver, base_domain)),
        ("click_int",    3, lambda: click_internal_link(driver, base_domain)),
        ("subpages",     3, lambda: navigate_subpages(driver, base_domain)),
        ("search",       2, lambda: interact_with_search(driver)),
        ("scroll_lazy",  2, lambda: scroll_page(driver)),
        ("media",        2, lambda: load_media_elements(driver)),
        ("ajax",         2, lambda: trigger_ajax_content(driver)),
        ("back_fwd",     1, lambda: back_and_forward(driver)),
        ("forms",        1, lambda: interact_with_forms(driver)),
    ]
    weighted = []
    for name, weight, fn in action_pool:
        weighted.extend([(name, fn)] * weight)

    for action_num in range(1, num_actions + 1):
        name, fn = random.choice(weighted)
        try:
            fn()
        except Exception:
            pass
        time.sleep(random.uniform(0.3, 1.0))

# --- TAB MANAGEMENT ---

def open_new_tab(driver, url):
    """Open a new tab, close the old one, and navigate to url."""
    try:
        old_handles = set(driver.window_handles)
        old_handle = driver.current_window_handle
        driver.execute_script("window.open('');")
        WebDriverWait(driver, 10).until(
            lambda d: len(d.window_handles) > len(old_handles)
        )
        new_handle = (set(driver.window_handles) - old_handles).pop()
        driver.switch_to.window(new_handle)
        driver.switch_to.window(old_handle)
        driver.close()
        driver.switch_to.window(new_handle)
        driver.get(url)
    except Exception:
        driver.get(url)
    time.sleep(random.uniform(3, 5))

# --- MAIN LOOP ---

def run(driver, num_sites, actions_per_site):
    sites = TOP_SITES[:]
    random.shuffle(sites)
    sites = sites[:num_sites]

    print(f"\n🌍 Will visit {len(sites)} sites with ~{actions_per_site} actions each.\n")

    for idx, domain in enumerate(sites, 1):
        url = f"https://www.{domain}"
        print(f"\n{'='*55}")
        print(f"🌐 [{idx}/{len(sites)}] Visiting: {domain}")
        print(f"{'='*55}")

        try:
            if idx > 1:
                open_new_tab(driver, url)
            else:
                driver.get(url)
                time.sleep(random.uniform(3, 5))
        except Exception as e:
            print(f"   ⚠️  Page load error (skipping): {e}")
            continue

        # Check if page loaded at all
        try:
            WebDriverWait(driver, 10).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
        except:
            print("   ⚠️  Page didn't fully load. Browsing anyway.")

        # Randomize action count slightly around the target
        n_actions = random.randint(max(2, actions_per_site - 2), actions_per_site + 3)
        print(f"   📋 Performing {n_actions} actions...")
        perform_actions(driver, domain, n_actions)
        print(f"   ✅ Done with {domain}")

        # Human-like pause between sites
        pause = random.uniform(2, 6)
        print(f"   ⏸️  Pausing {pause:.1f}s before next site...")
        time.sleep(pause)

    print(f"\n🏁 Finished visiting {len(sites)} sites.")

# --- ENTRY POINT ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect non-LLM web traffic data.")
    parser.add_argument("--browser", choices=["chrome", "firefox"], default="chrome",
                        help="Browser to use (default: chrome)")
    parser.add_argument("--num-sites", type=int, default=100,
                        help="Number of sites to visit (default: 100, max: 100)")
    parser.add_argument("--actions-per-site", type=int, default=10,
                        help="Approximate number of actions per site (default: 10)")
    args = parser.parse_args()

    if args.browser == "chrome" and not os.path.exists("/Applications/Google Chrome.app"):
        print("❌ Google Chrome not found at /Applications/Google Chrome.app")
        sys.exit(1)

    driver = launch_browser(args.browser)

    try:
        run(driver, min(args.num_sites, len(TOP_SITES)), args.actions_per_site)
    except KeyboardInterrupt:
        print("\n🛑 Stopped.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        print("👋 Closing Chrome.")
        driver.quit()
