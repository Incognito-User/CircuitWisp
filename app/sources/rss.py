# app/sources/rss.py
# ---------------------------------------------------------------------------
# RSS CHATTER SOURCE MODULE
# Fetches RSS feeds (e.g., SecurityWeek) and checks for CVE mentions.
# Produces ExploitRecord objects tagged as 'rss'.
# ---------------------------------------------------------------------------

import httpx
import logging
from datetime import datetime
from typing import List

from app.models import ExploitRecord

logger = logging.getLogger(__name__)

# SecurityWeek blocks default Python clients → use browser UA
SECURITYWEEK_RSS = "https://www.securityweek.com/feed"

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/118.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


# ---------------------------------------------------------------------------
# Fetch RSS Chatter
# ---------------------------------------------------------------------------
async def fetch_rss_chatter(cve_id: str) -> List[ExploitRecord]:
    """
    Fetch RSS-based chatter for a CVE.
    Safe fallback: returns empty list on failure.
    """
    records: List[ExploitRecord] = []

    try:
        async with httpx.AsyncClient(
            timeout=15,
            follow_redirects=True,
            headers=BROWSER_HEADERS,
        ) as client:
            resp = await client.get(SECURITYWEEK_RSS)
            resp.raise_for_status()
            text = resp.text

    except Exception as exc:
        logger.warning(f"RSS fetch failed for {cve_id}: {exc}")
        return []

    # Simple heuristic: CVE appears in feed text
    if cve_id and cve_id.upper() in text.upper():
        records.append(
            ExploitRecord(
                source="rss",
                cve_id=cve_id,
                title=f"RSS chatter mentioning {cve_id}",
                url=SECURITYWEEK_RSS,
                published=datetime.utcnow(),
                reliability=0.6,
            )
        )

    return records
