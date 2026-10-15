# app/sources/metasploit.py
# ---------------------------------------------------------------------------
# Metasploit ingestion module
# Uses GitHub Code Search API for CVE-specific module discovery.
# Provides recent module discovery via official RSS feed.
# ---------------------------------------------------------------------------

import os
import re
import httpx
import logging
import feedparser
from typing import List, Dict, Any

from app.models import ExploitRecord

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# GitHub API endpoints (validated)
# ---------------------------------------------------------------------------
METASPLOIT_PRIMARY_URL = (
    "https://api.github.com/search/code?q={cve}+repo:rapid7/metasploit-framework"
)

METASPLOIT_FALLBACK_URL = (
    "https://api.github.com/search/code?q={cve}+in:file"
)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


# ---------------------------------------------------------------------------
# Parse GitHub search results → ExploitRecord list
# ---------------------------------------------------------------------------
def parse_metasploit_results(data: dict, cve_id: str) -> List[ExploitRecord]:
    items = data.get("items", [])
    records = []

    for item in items:
        try:
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")

            if "modules" not in file_path:
                continue

            record = ExploitRecord(
                source="metasploit",
                cve_id=cve_id,
                title=f"Metasploit module: {file_path}",
                url=html_url,
                published=None,
                reliability="high",
            )
            records.append(record)

        except Exception as exc:
            logger.warning("Failed to parse Metasploit record", extra={"error": str(exc)})

    return records


# ---------------------------------------------------------------------------
# Fetch Metasploit modules for a specific CVE
# ---------------------------------------------------------------------------
async def fetch_metasploit(cve_id: str) -> List[ExploitRecord]:
    if not GITHUB_TOKEN:
        logger.warning("GITHUB_TOKEN not set — Metasploit search disabled.")
        return []

    urls = [
        METASPLOIT_PRIMARY_URL.format(cve=cve_id),
        METASPLOIT_FALLBACK_URL.format(cve=cve_id),
    ]

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }

    for url in urls:
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                records = parse_metasploit_results(data, cve_id)
                return records

        except Exception as exc:
            logger.warning("Metasploit fetch failed", extra={"url": url, "error": str(exc)})

    return []


# ---------------------------------------------------------------------------
# Fetch recent Metasploit modules (for trending discovery)
# ---------------------------------------------------------------------------
async def fetch_metasploit_recent(limit: int = 50) -> List[Dict[str, Any]]:
    url = "https://metasploit.com/modules/rss.xml"

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            feed = feedparser.parse(resp.text)
    except Exception as exc:
        logger.warning("Metasploit recent fetch failed", extra={"error": str(exc)})
        return []

    results = []
    for entry in feed.entries[:limit]:
        cve_id = None
        text = f"{entry.get('title', '')} {entry.get('summary', '')}"
        match = re.search(r"CVE-\d{4}-\d+", text)
        if match:
            cve_id = match.group(0)

        results.append({
            "cve_id": cve_id,
            "title": entry.get("title"),
            "published": entry.get("published"),
            "url": entry.get("link"),
            "source": "metasploit",
        })

    return results
