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
    print(f"   Profile: {CHROME_PROFILE_PATH}")
    os.makedirs(CHROME_PROFILE_PATH, exist_ok=True)

    options = uc.ChromeOptions()
    options.add_argument(f"--user-data-dir={CHROME_PROFILE_PATH}")
    options.add_argument(f"--ssl-key-log-file={sslkeylog_path}")

    # Use a unique debugging port so this can run alongside other Chrome instances
    debug_port = random.randint(9200, 9399)
    options.add_argument(f"--remote-debugging-port={debug_port}")

    try:
        driver = uc.Chrome(options=options, version_main=145)
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

# --- HUMAN-LIKE ACTIONS ---

def scroll_page(driver):
    """Scroll the page in a human-like pattern."""
    direction = random.choice(["down", "down", "down", "up"])  # bias downward
    distance = random.randint(200, 800)
    if direction == "up":
        distance = -distance
    driver.execute_script(f"window.scrollBy(0, {distance});")
    time.sleep(random.uniform(0.8, 2.5))

def read_pause(driver):
    """Simulate reading/looking at the page."""
    time.sleep(random.uniform(2.0, 6.0))

def click_internal_link(driver, base_domain):
    """Click a random visible internal link on the page."""
    try:
        links = driver.find_elements(By.CSS_SELECTOR, "a[href]")
        visible_links = []
        for link in links:
            try:
                href = link.get_attribute("href") or ""
                # Only follow internal links (same domain) or relative paths
                parsed = urlparse(href)
                if not parsed.netloc or base_domain in parsed.netloc:
                    if link.is_displayed() and link.size["height"] > 0:
                        visible_links.append(link)
            except:
                continue

        if not visible_links:
            return False

        chosen = random.choice(visible_links[:20])  # pick from first 20 visible
        print(f"      🔗 Clicking: {chosen.text[:60] or chosen.get_attribute('href')[:60]}")
        driver.execute_script("arguments[0].click();", chosen)
        time.sleep(random.uniform(2.0, 4.0))
        return True
    except:
        return False

def interact_with_search(driver):
    """Try to find and type into a search box."""
    search_selectors = [
        "input[type='search']",
        "input[name='q']",
        "input[name='query']",
        "input[name='search']",
        "input[placeholder*='earch']",
        "input[aria-label*='earch']",
    ]
    search_terms = [
        "weather today", "best restaurants", "how to cook pasta",
        "latest news", "movie reviews", "travel deals",
        "python tutorial", "home improvement", "fitness tips",
    ]
    for selector in search_selectors:
        try:
            box = driver.find_element(By.CSS_SELECTOR, selector)
            if box.is_displayed():
                box.click()
                time.sleep(random.uniform(0.3, 0.8))
                term = random.choice(search_terms)
                print(f"      🔍 Searching: {term}")
                for char in term:
                    box.send_keys(char)
                    time.sleep(random.uniform(0.04, 0.12))
                time.sleep(random.uniform(0.5, 1.0))
                box.send_keys(Keys.ENTER)
                time.sleep(random.uniform(2.0, 4.0))
                return True
        except:
            continue
    return False

def hover_elements(driver):
    """Move mouse over random elements to trigger hover effects / preloads."""
    from selenium.webdriver.common.action_chains import ActionChains
    try:
        elements = driver.find_elements(By.CSS_SELECTOR, "a, button, img, div.card, article")
        visible = [e for e in elements if e.is_displayed()][:30]
        if visible:
            target = random.choice(visible)
            ActionChains(driver).move_to_element(target).perform()
            time.sleep(random.uniform(0.5, 1.5))
    except:
        pass

def perform_actions(driver, base_domain, num_actions):
    """Perform a series of random human-like actions on the current page."""
    action_pool = [
        ("scroll", lambda: scroll_page(driver)),
        ("scroll", lambda: scroll_page(driver)),        # weighted more
        ("read",   lambda: read_pause(driver)),
        ("read",   lambda: read_pause(driver)),          # weighted more
        ("click",  lambda: click_internal_link(driver, base_domain)),
        ("search", lambda: interact_with_search(driver)),
        ("hover",  lambda: hover_elements(driver)),
    ]

    for action_num in range(1, num_actions + 1):
        name, fn = random.choice(action_pool)
        try:
            fn()
        except Exception:
            pass
        # Small pause between actions
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

        if idx > 1:
            open_new_tab(driver, url)
        else:
            try:
                driver.get(url)
                time.sleep(random.uniform(3, 5))
            except Exception as e:
                print(f"   ⚠️  Page load error: {e}")
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
    parser.add_argument("--actions-per-site", type=int, default=6,
                        help="Approximate number of actions per site (default: 6)")
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
