# app/sources/github.py
# ---------------------------------------------------------------------------
# GitHub PoC ingestion module
# Uses GitHub Code Search API for CVE-specific PoC discovery.
# Provides recent PoC discovery via keyword search.
# ---------------------------------------------------------------------------

import os
import re
import httpx
import logging
from typing import List, Dict, Any

from app.models import ExploitRecord

logger = logging.getLogger(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

GITHUB_SEARCH_URL = "https://api.github.com/search/code?q={query}"


# ---------------------------------------------------------------------------
# Parse GitHub search results → ExploitRecord list
# ---------------------------------------------------------------------------
def parse_github_results(data: dict, cve_id: str) -> List[ExploitRecord]:
    items = data.get("items", [])
    records = []

    for item in items:
        try:
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")
            repo = item.get("repository", {}).get("full_name", "unknown")

            record = ExploitRecord(
                source="github",
                cve_id=cve_id,
                title=f"GitHub PoC: {file_path}",
                url=html_url,
                published=None,
                reliability="medium",
            )
            records.append(record)

        except Exception as exc:
            logger.warning("Failed to parse GitHub PoC", extra={"error": str(exc)})

    return records


# ---------------------------------------------------------------------------
# Fetch GitHub PoCs for a specific CVE
# ---------------------------------------------------------------------------
async def fetch_github(cve_id: str) -> List[ExploitRecord]:
    if not GITHUB_TOKEN:
        logger.warning("GITHUB_TOKEN not set — GitHub PoC search disabled.")
        return []

    url = GITHUB_SEARCH_URL.format(query=cve_id)

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return parse_github_results(data, cve_id)
    except Exception as exc:
        logger.warning("GitHub PoC fetch failed", extra={"error": str(exc)})
        return []


# ---------------------------------------------------------------------------
# Fetch recent GitHub PoCs (for trending discovery)
# ---------------------------------------------------------------------------
async def fetch_github_recent(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Discover recent GitHub PoCs by searching for CVE patterns.
    """

    if not GITHUB_TOKEN:
        logger.warning("GITHUB_TOKEN not set — GitHub recent search disabled.")
        return []

    query = "CVE-20"
    url = GITHUB_SEARCH_URL.format(query=query)

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("GitHub recent PoC fetch failed", extra={"error": str(exc)})
        return []

    results = []
    for item in data.get("items", [])[:limit]:
        text = f"{item.get('path', '')} {item.get('name', '')}"
        match = re.search(r"CVE-\d{4}-\d+", text)
        cve_id = match.group(0) if match else None

        results.append({
            "cve_id": cve_id,
            "title": item.get("name"),
            "published": None,
            "url": item.get("html_url"),
            "source": "github",
        })

    return results
