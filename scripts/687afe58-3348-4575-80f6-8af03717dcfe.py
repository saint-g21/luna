#!/usr/bin/env python3
"""
Metasploit Module Scraper – extract exploit metadata from GitHub.
Requires a GitHub token for API access (no scraping fallback due to complexity).
"""

import requests, csv, logging, sys, re, time, os, argparse, base64

GITHUB_TOKEN = ""               # Paste your token
API_BASE = "https://api.github.com"
REPO_OWNER = "rapid7"
REPO_NAME = "metasploit-framework"
BRANCH = "master"
OUTPUT_CSV = "metasploit_modules.csv"

USER_AGENTS = ["Mozilla/5.0 ..."]
PROXY_LIST = [None]
TIMEOUT = 20

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)

def sanitize(v):
    if not v: return ""
    v = str(v).strip()
    if v and v[0] in "=+-@\t\r": v = "\t"+v
    return v

def get_headers():
    h = {"User-Agent": random.choice(USER_AGENTS)}
    if GITHUB_TOKEN:
        h["Authorization"] = f"token {GITHUB_TOKEN}"
    return h

def fetch_api(url):
    for attempt in range(3):
        try:
            resp = requests.get(url, headers=get_headers(),
                                proxies=random.choice(PROXY_LIST), timeout=TIMEOUT)
            if resp.status_code == 403:
                logger.error("Rate limited. Wait and retry or use token.")
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"Attempt {attempt+1}: {e}")
            time.sleep(5)
    return None

def list_files_recursive(path="modules/exploits"):
    """Recursively list all .rb files in the exploit directory."""
    url = f"{API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/contents/{path}?ref={BRANCH}"
    items = fetch_api(url)
    if not items:
        return []
    files = []
    for item in items:
        if item["type"] == "dir":
            # Recursively go deeper
            sub_files = list_files_recursive(item["path"])
            files.extend(sub_files)
            time.sleep(0.1)
        elif item["name"].endswith(".rb"):
            files.append(item)
    return files

def parse_module_metadata(content):
    """Extract info from the Ruby module header."""
    info = {
        "name": "",
        "description": "",
        "references": "",
        "platform": "",
        "type": ""
    }
    # Look for the 'Name' and 'Description' in the metadata
    name_match = re.search(r"'Name'\s*=>\s*'(.+?)'", content)
    if name_match:
        info["name"] = name_match.group(1)
    desc_match = re.search(r"'Description'\s*=>\s*%q[{(](.+?)[})]", content, re.DOTALL)
    if desc_match:
        info["description"] = desc_match.group(1).strip()
    # Platform
    plat_match = re.search(r"'Platform'\s*=>\s*\[(.+?)\]", content)
    if plat_match:
        info["platform"] = plat_match.group(1).replace("'", "").replace('"', '')
    # References (CVE, BID, etc.)
    refs = re.findall(r"(?:CVE-\d{4}-\d{4,}|OSVDB-\d+|EDB-ID-\d+)", content)
    info["references"] = ", ".join(set(refs))
    return info

def main():
    if not GITHUB_TOKEN:
        logger.error("GitHub token required. Set GITHUB_TOKEN variable.")
        return

    logger.info("Listing Metasploit exploit modules...")
    files = list_files_recursive()
    logger.info(f"Found {len(files)} .rb files.")

    modules = []
    for idx, f in enumerate(files[:50]):  # limit to 50 for speed
        logger.info(f"Processing {idx+1}/{min(50,len(files))}: {f['path']}")
        # Fetch file content via API
        content_url = f["url"] + f"?ref={BRANCH}"
        file_data = fetch_api(content_url)
        if not file_data or "content" not in file_data:
            continue
        decoded = base64.b64decode(file_data["content"]).decode("utf-8", errors="ignore")
        meta = parse_module_metadata(decoded)
        modules.append({
            "path": sanitize(f["path"]),
            "name": sanitize(meta["name"]),
            "description": sanitize(meta["description"]),
            "platform": sanitize(meta["platform"]),
            "references": sanitize(meta["references"])
        })
        time.sleep(0.5)  # avoid secondary rate limit

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["path","name","description","platform","references"])
        writer.writeheader()
        writer.writerows(modules)

    logger.info(f"Saved {len(modules)} modules to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
