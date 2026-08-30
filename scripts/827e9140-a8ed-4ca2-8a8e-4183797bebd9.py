#!/usr/bin/env python3
"""
IOC Extractor – pulls IPs, domains, hashes, and CVEs from a blog post.
"""

import requests, csv, logging, sys, re, random, time
from bs4 import BeautifulSoup

URL = "https://medium.com/threat-report-2024"
OUTPUT_CSV = "medium-iocs.csv"
PROXY_LIST = [None]
USER_AGENTS = ["Mozilla/5.0 ..."]
TIMEOUT = 15

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)

def sanitize(v):
    if not v: return ""
    v = str(v).strip()
    if v and v[0] in "=+-@\t\r": v = "\t"+v
    return v

def get_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}

def fetch(session, url):
    for attempt in range(3):
        try:
            resp = session.get(url, headers=get_headers(),
                               proxies=random.choice(PROXY_LIST), timeout=TIMEOUT)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            logger.error(f"Attempt {attempt+1}: {e}")
            time.sleep(2)
    return None

def extract_iocs(text):
    """Apply regex patterns to find IOCs."""
    iocs = []
    # IPv4 addresses
    for m in re.finditer(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text):
        iocs.append(("ip", m.group()))
    # Domains (simple)
    for m in re.finditer(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text):
        domain = m.group().lower()
        if not domain.endswith(('.com','.org','.net','.io','.gov','.edu','.uk')):
            continue  # filter noise
        iocs.append(("domain", domain))
    # MD5/SHA1/SHA256 hashes
    for m in re.finditer(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text):
        iocs.append(("hash", m.group()))
    # CVE IDs
    for m in re.finditer(r'CVE-\d{4}-\d{4,}', text):
        iocs.append(("cve", m.group()))
    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for t,v in iocs:
        if (t,v) not in seen:
            seen.add((t,v))
            unique.append((t,v))
    return unique

def main():
    session = requests.Session()
    html = fetch(session, URL)
    if not html:
        return

    soup = BeautifulSoup(html, "html.parser")
    # Extract all text from the main content (adjust selector to the article body)
    article = soup.find("article") or soup.find("div", class_="post-content") or soup.body
    if not article:
        logger.error("Could not locate article content.")
        return
    text = article.get_text(" ", strip=True)

    iocs = extract_iocs(text)
    if not iocs:
        logger.info("No IOCs found.")
        return

    rows = [{"type": t, "value": v} for t,v in iocs]
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["type","value"])
        writer.writeheader()
        writer.writerows(rows)

    logger.info(f"Extracted {len(rows)} IOCs → {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
