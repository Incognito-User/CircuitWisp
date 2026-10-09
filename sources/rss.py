import httpx
import logging
from datetime import datetime, timezone
from typing import Dict, List

import feedparser

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

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

RSS_CACHE: Dict[str, Dict] = {}


def _safe_parse_timestamp_struct(ts_struct) -> datetime:
    if not ts_struct:
        return datetime.now(timezone.utc)
    try:
        return datetime(*ts_struct[:6], tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _safe_reliability_feed(feed_url: str) -> float:
    domain = feed_url.split("//")[1].split("/")[0].split(".")[0]
    return SOURCE_RELIABILITY.get(domain, 0.7)


async def fetch_rss_chatter(cve_id: str) -> List[ExploitRecord]:
    results: List[ExploitRecord] = []

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        for feed_url in RSS_FEEDS:
            start = datetime.now(timezone.utc)
            try:
                resp = await client.get(feed_url, headers={"User-Agent": "CircuitWisp/1.0"})
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                logger.warning("RSS fetch failed", exc=str(exc), url=feed_url)
                RSS_CACHE[feed_url] = {
                    "error": str(exc),
                    "parsed": None,
                    "latency_ms": (datetime.now(timezone.utc) - start).total_seconds() * 1000,
                }
                continue
            except Exception as exc:
                logger.warning("RSS unexpected error", exc=str(exc), url=feed_url)
                RSS_CACHE[feed_url] = {
                    "error": str(exc),
                    "parsed": None,
                    "latency_ms": (datetime.now(timezone.utc) - start).total_seconds() * 1000,
                }
                continue

            parsed = feedparser.parse(resp.text)
            RSS_CACHE[feed_url] = {
                "error": None,
                "parsed": parsed,
                "latency_ms": (datetime.now(timezone.utc) - start).total_seconds() * 1000,
            }

            reliability = _safe_reliability_feed(feed_url)

            for entry in parsed.entries:
                title = entry.get("title", "")
                summary = entry.get("summary", "")
                link = entry.get("link", "")

                text = (title + " " + summary).lower()
                if cve_id.lower() not in text:
                    continue

                published_struct = entry.get("published_parsed") or entry.get("updated_parsed")
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

    logger.info("RSS chatter fetched", count=len(results), cve=cve_id)
    return results
