import httpx
import logging
from datetime import datetime
from typing import Dict, List

import feedparser

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RSS feeds and reliability weights
# ---------------------------------------------------------------------------

RSS_FEEDS: List[str] = [
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.securityweek.com/securityweek",
    "https://www.debian.org/security/dsa.atom",
]

SOURCE_RELIABILITY: Dict[str, float] = {
    "bleepingcomputer": 0.9,
    "securityweek": 0.85,
    "debian": 0.8,
}

# Cache structure:
# RSS_CACHE[feed_url] = {
#     "parsed": feedparser object or None,
#     "error": str or None,
#     "latency_ms": float
# }
RSS_CACHE: Dict[str, Dict] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_parse_timestamp_struct(ts_struct) -> datetime:
    """Convert feedparser time struct to datetime."""
    if not ts_struct:
        return datetime.utcnow()
    try:
        return datetime(*ts_struct[:6])
    except Exception:
        return datetime.utcnow()


def _safe_reliability_feed(feed_url: str) -> float:
    """Return reliability score based on feed domain."""
    domain = feed_url.split("//")[1].split("/")[0].split(".")[0]
    return SOURCE_RELIABILITY.get(domain, 0.7)


# ---------------------------------------------------------------------------
# Main RSS ingestion
# ---------------------------------------------------------------------------

async def fetch_rss_chatter(cve_id: str) -> List[ExploitRecord]:
    results: List[ExploitRecord] = []

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        for feed_url in RSS_FEEDS:
            start = datetime.utcnow()

            try:
                resp = await client.get(feed_url, headers={"User-Agent": "CircuitWisp/1.0"})
                resp.raise_for_status()
            except Exception as exc:
                # FIXED LOGGING — no invalid keyword args
                logger.warning(f"RSS fetch failed for {feed_url}: {exc}")

                RSS_CACHE[feed_url] = {
                    "parsed": None,
                    "error": str(exc),
                    "latency_ms": (datetime.utcnow() - start).total_seconds() * 1000,
                }
                continue

            # Parse feed
            parsed = feedparser.parse(resp.text)

            RSS_CACHE[feed_url] = {
                "parsed": parsed,
                "error": None,
                "latency_ms": (datetime.utcnow() - start).total_seconds() * 1000,
            }

            reliability = _safe_reliability_feed(feed_url)

            # Iterate entries
            for entry in parsed.entries:
                title = entry.get("title", "")
                summary = entry.get("summary", "")
                link = entry.get("link", "")

                text = (title + " " + summary).lower()
                if cve_id.lower() not in text:
                    continue

                published_struct = (
                    entry.get("published_parsed")
                    or entry.get("updated_parsed")
                )
                published = _safe_parse_timestamp_struct(published_struct)

                record = ExploitRecord(
                    source="rss",
                    cve_id=cve_id,
                    title=title,
                    url=link or feed_url,
                    published=published,
                    reliability=reliability,
                )

                results.append(record)

    logger.info(f"RSS chatter fetched for {cve_id}: {len(results)} records")
    return results
