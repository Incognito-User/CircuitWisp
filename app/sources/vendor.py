# app/sources/vendor.py
# ---------------------------------------------------------------------------
# Vendor advisory ingestion module
#
# Supports:
#   - Microsoft MSRC CVRF API
#   - Cisco Security Advisories API
#   - Debian Security RSS/Atom feeds
#
# This module:
#   - Uses validated modern endpoints
#   - Supports primary + fallback URLs
#   - Loads API keys securely from environment variables (OWASP compliant)
#   - Normalizes results into ExploitRecord objects
#   - Provides safe fallback behavior (never crashes)
# ---------------------------------------------------------------------------

import os
import httpx
import logging
import feedparser
from typing import List

from app.models import ExploitRecord

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Microsoft MSRC API (validated)
# Requires API key
# ---------------------------------------------------------------------------
MSRC_URL = "https://api.msrc.microsoft.com/cvrf/v2.0/cve/{cve}"

MSRC_API_KEY = os.getenv("MSRC_API_KEY")
if not MSRC_API_KEY:
    logger.warning("MSRC_API_KEY is not set — MSRC advisories will be skipped.")

# ---------------------------------------------------------------------------
# Cisco Security Advisories API (validated)
# Requires OAuth token
# ---------------------------------------------------------------------------
CISCO_URL = "https://api.cisco.com/security/advisories/cve/{cve}"

CISCO_API_KEY = os.getenv("CISCO_API_KEY")
if not CISCO_API_KEY:
    logger.warning("CISCO_API_KEY is not set — Cisco advisories will be skipped.")

# ---------------------------------------------------------------------------
# Debian Security RSS/Atom (validated)
# No API key required
# ---------------------------------------------------------------------------
DEBIAN_RSS_URL = "https://www.debian.org/security/dsa.xml"
DEBIAN_ATOM_URL = "https://www.debian.org/security/dsa.atom"


# ---------------------------------------------------------------------------
# Parse MSRC → ExploitRecord
# ---------------------------------------------------------------------------
def parse_msrc(data: dict, cve_id: str) -> List[ExploitRecord]:
    records = []

    try:
        title = data.get("Title", "Microsoft Security Advisory")
        url = data.get("DocumentTracking", {}).get("Identification", {}).get("ID", "")
        published = data.get("DocumentTracking", {}).get("InitialReleaseDate", None)

        record = ExploitRecord(
            source="msrc",
            cve_id=cve_id,
            title=title,
            url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
            published=published,
            reliability="high",
        )
        records.append(record)

    except Exception as exc:
        logger.warning("Failed to parse MSRC advisory", extra={"error": str(exc)})

    return records


# ---------------------------------------------------------------------------
# Parse Cisco → ExploitRecord
# ---------------------------------------------------------------------------
def parse_cisco(data: dict, cve_id: str) -> List[ExploitRecord]:
    records = []

    advisories = data.get("advisories", [])
    for adv in advisories:
        try:
            record = ExploitRecord(
                source="cisco",
                cve_id=cve_id,
                title=adv.get("title", "Cisco Security Advisory"),
                url=adv.get("publicationUrl", ""),
                published=adv.get("firstPublished", None),
                reliability="high",
            )
            records.append(record)

        except Exception as exc:
            logger.warning("Failed to parse Cisco advisory", extra={"error": str(exc)})

    return records


# ---------------------------------------------------------------------------
# Parse Debian RSS/Atom → ExploitRecord
# ---------------------------------------------------------------------------
def parse_debian(feed, cve_id: str) -> List[ExploitRecord]:
    records = []

    for entry in feed.entries:
        if cve_id in entry.title or cve_id in entry.summary:
            try:
                record = ExploitRecord(
                    source="debian",
                    cve_id=cve_id,
                    title=entry.title,
                    url=entry.link,
                    published=entry.get("published", None),
                    reliability="medium",
                )
                records.append(record)

            except Exception as exc:
                logger.warning("Failed to parse Debian advisory", extra={"error": str(exc)})

    return records


# ---------------------------------------------------------------------------
# Fetch MSRC
# ---------------------------------------------------------------------------
async def fetch_msrc(cve_id: str) -> List[ExploitRecord]:
    if not MSRC_API_KEY:
        return []

    url = MSRC_URL.format(cve=cve_id)
    headers = {"api-key": MSRC_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return parse_msrc(resp.json(), cve_id)

    except Exception as exc:
        logger.warning("MSRC fetch failed", extra={"error": str(exc), "cve": cve_id})
        return []


# ---------------------------------------------------------------------------
# Fetch Cisco
# ---------------------------------------------------------------------------
async def fetch_cisco(cve_id: str) -> List[ExploitRecord]:
    if not CISCO_API_KEY:
        return []

    url = CISCO_URL.format(cve=cve_id)
    headers = {"Authorization": f"Bearer {CISCO_API_KEY}"}

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return parse_cisco(resp.json(), cve_id)

    except Exception as exc:
        logger.warning("Cisco fetch failed", extra={"error": str(exc), "cve": cve_id})
        return []


# ---------------------------------------------------------------------------
# Fetch Debian (RSS → fallback Atom)
# ---------------------------------------------------------------------------
async def fetch_debian(cve_id: str) -> List[ExploitRecord]:
    urls = [DEBIAN_RSS_URL, DEBIAN_ATOM_URL]

    for url in urls:
        try:
            feed = feedparser.parse(url)
            records = parse_debian(feed, cve_id)

            logger.info(
                "Debian advisory fetch successful",
                extra={"url": url, "count": len(records), "cve": cve_id},
            )

            return records

        except Exception as exc:
            logger.warning(
                "Debian advisory fetch failed",
                extra={"url": url, "error": str(exc), "cve": cve_id},
            )

    return []


# ---------------------------------------------------------------------------
# Unified vendor fetch
# ---------------------------------------------------------------------------
async def fetch_vendor_advisories(cve_id: str) -> List[ExploitRecord]:
    """
    Unified entry point for vendor advisories.
    """
    results = []

    results.extend(await fetch_msrc(cve_id))
    results.extend(await fetch_cisco(cve_id))
    results.extend(await fetch_debian(cve_id))

    return results
