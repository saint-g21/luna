#!/usr/bin/env python3
"""
GitHub OSINT Scraper – collects repos from a user, filtering for security tools.
"""

import requests, csv, logging, sys, random, time, os, argparse
from bs4 import BeautifulSoup

# ---------- CONFIG ----------
GITHUB_API = "https://api.github.com"
PROXY_LIST = [None]
USER_AGENTS = ["Mozilla/5.0 ..."]
TIMEOUT = 15
OUTPUT_CSV = "github_repos.csv"
GITHUB_TOKEN = ""                # Optional token for API

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)

def sanitize(val):
    if not val: return ""
    v = str(val).strip()
    if v and v[0] in "=+-@\t\r": v = "\t"+v
    return v

def get_headers():
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers

def fetch_api(url):
    for attempt in range(3):
        try:
            resp = requests.get(url, headers=get_headers(),
                                proxies=random.choice(PROXY_LIST), timeout=TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"API attempt {attempt+1}: {e}")
            time.sleep(2)
    return None

def fetch_html(session, url):
    try:
        resp = session.get(url, headers=get_headers(),
                           proxies=random.choice(PROXY_LIST), timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        logger.error(f"HTML fetch failed: {e}")
        return None

def get_repos_api(username):
    """Use GitHub REST API (fast & structured)."""
    repos = []
    page = 1
    while True:
        url = f"{GITHUB_API}/users/{username}/repos?per_page=100&page={page}"
        data = fetch_api(url)
        if not data or len(data)==0:
            break
        for repo in data:
            # Filter only repos that sound like security tools
            name = repo["name"]
            desc = repo.get("description","")
            if any(kw in name.lower()+desc.lower() for kw in
                   ["exploit","metasploit","nmap","brute","crack","hack","pentest","cve"]):
                repos.append({
                    "name": sanitize(repo["name"]),
                    "description": sanitize(desc),
                    "language": sanitize(repo.get("language","")),
                    "stars": repo.get("stargazers_count",0),
                    "url": sanitize(repo["html_url"])
                })
        page += 1
        time.sleep(1)  # Rate limit
    return repos

def get_repos_html(username):
    """Fallback: scrape the GitHub profile page."""
    session = requests.Session()
    url = f"https://github.com/{username}?tab=repositories"
    html = fetch_html(session, url)
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    repos = []
    for li in soup.select("li.col-12"):
        name_el = li.find("a", itemprop="name codeRepository")
        if not name_el: continue
        name = name_el.text.strip()
        desc_el = li.find("p", itemprop="description")
        desc = desc_el.text.strip() if desc_el else ""
        lang_el = li.find("span", itemprop="programmingLanguage")
        lang = lang_el.text.strip() if lang_el else ""
        repos.append({
            "name": sanitize(name),
            "description": sanitize(desc),
            "language": sanitize(lang),
            "stars": 0,          # harder to extract via HTML
            "url": sanitize(f"https://github.com{name_el['href']}")
        })
    return repos

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", required=True, help="GitHub username")
    args = parser.parse_args()

    if GITHUB_TOKEN:
        logger.info("Using GitHub API...")
        repos = get_repos_api(args.user)
    else:
        logger.warning("No token – falling back to scraping (limited data).")
        repos = get_repos_html(args.user)

    if not repos:
        logger.error("No security-related repos found.")
        return

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=repos[0].keys())
        writer.writeheader()
        writer.writerows(repos)

    logger.info(f"Extracted {len(repos)} security tools → {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
