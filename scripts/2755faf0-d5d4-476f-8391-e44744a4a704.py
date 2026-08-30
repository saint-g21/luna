#!/usr/bin/env python3
"""
WHOIS Scraper — Domain Registration & Ownership Intelligence
=============================================================

Harvests:
- Registrar, creation/expiration dates
- Name servers (reveals hosting infrastructure)
- Abuse contacts
- Organization details

Uses python-whois library. Falls back to RDAP for TLDs not supported.
"""

import subprocess
import json
from typing import Dict, Any
from scripts.base_scraper import BaseScraper, ScrapeResult


class WhoisScraper(BaseScraper):
    """
    WHOIS harvester. Safe, read-only OSINT.
    
    Usage:
        w = WhoisScraper()
        result = w.execute("example.com")
        print(result.data["registrar"], result.data["name_servers"])
    """
    
    def __init__(self, rate_limit_rps: float = 1.0, output_manager=None):
        super().__init__("whois", rate_limit_rps, output_manager)
    
    def run(self, target: str) -> ScrapeResult:
        # Clean target (strip protocol if present)
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        
        # Try python-whois first
        try:
            import whois
            w = whois.whois(domain)
            
            data = {
                "domain": domain,
                "registrar": w.registrar if hasattr(w, 'registrar') else None,
                "creation_date": str(w.creation_date) if hasattr(w, 'creation_date') else None,
                "expiration_date": str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                "name_servers": w.name_servers if hasattr(w, 'name_servers') else [],
                "emails": w.emails if hasattr(w, 'emails') else [],
                "org": w.org if hasattr(w, 'org') else None,
                "country": w.country if hasattr(w, 'country') else None,
            }
            
            raw = json.dumps(data, indent=2, default=str)
            return ScrapeResult("whois", domain, True, data, raw)
            
        except ImportError:
            # Fallback: shell whois command
            result = subprocess.run(
                ["whois", domain],
                capture_output=True,
                text=True,
                timeout=30
            )
            raw = result.stdout
            
            # Parse key lines
            data = {"domain": domain, "raw_parsed": {}}
            for line in raw.splitlines():
                if ":" in line and not line.startswith("%"):
                    key, val = line.split(":", 1)
                    data["raw_parsed"][key.strip()] = val.strip()
            
            return ScrapeResult("whois", domain, result.returncode == 0, data, raw)
        
        except Exception as e:
            return ScrapeResult("whois", domain, False, {}, "", str(e))
