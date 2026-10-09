import logging
import asyncio
import re
from datetime import datetime
from time import time
from urllib.parse import urlparse

import httpx
import feedparser

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

SEM = asyncio.Semaphore(5)

RSS_FEEDS = [
    "https://packetstormsecurity.com/rss/",
    "https://seclists.org/rss/fulldisclosure.rss",
    "https://seclists.org/rss/bugtraq.rss",
    "https://attackerkb.com/feed.xml",
    "https://isc.sans.edu/rssfeed.xml",
    "https://msrc.microsoft.com/blog/feed",
    "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
    "https://access.redhat.com/security/updates/rss",
    "https://ubuntu.com/security/notices/rss.xml",
    "https://www.debian.org/security/dsa.en.rdf",
    "https://www.vmware.com/security/advisories.xml",
    "https://krebsonsecurity.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://feeds.securityweek.com/securityweek",
    "https://www.darkreading.com/rss.xml",
]

SOURCE_RELIABILITY = {
    "packetstormsecurity": 0.9,
    "seclists": 0.8,
    "attackerkb": 0.95,
    "isc": 0.85,
    "msrc": 1.0,
    "cisco": 1.0,
    "redhat": 1.0,
    "ubuntu": 1.0,
    "debian": 1.0,
    "vmware": 1.0,
    "krebsonsecurity": 0.9,
    "bleepingcomputer": 0.8,
    "thehackersnews": 0.7,
    "securityweek": 0.7,
    "darkreading": 0.7,
}

RSS_CACHE = {}
CACHE_TTL = 300  # 5 minutes


async def fetch_rss_chatter(cve_id: str) -> list[ExploitRecord]:
    results = []
    seen = set()

    pattern = re.compile(rf"\b{re.escape(cve_id)}\b", re.IGNORECASE)

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        for feed_url in RSS_FEEDS:

            domain = _extract_domain(feed_url)
            reliability = SOURCE_RELIABILITY.get(domain, 0.5)

            try:
                cached = RSS_CACHE.get(feed_url)
                if cached and (time() - cached["timestamp"] < CACHE_TTL):
                    parsed = cached["parsed"]
                else:
                    async with SEM:
                        resp = await client.get(feed_url)
                        resp.raise_for_status()

                    parsed = feedparser.parse(resp.text)

                    RSS_CACHE[feed_url] = {
                        "parsed": parsed,
                        "timestamp": time(),
                        "bozo": parsed.bozo,
                        "error": str(parsed.bozo_exception) if parsed.bozo else None,
                        "entries": len(parsed.entries),
                    }

            except httpx.HTTPError as exc:
                logger.warning("RSS fetch failed", feed=feed_url, error=str(exc))
                continue

            for entry in parsed.entries:
                title = entry.get("title", "")
                summary = _extract_summary(entry)

                if not pattern.search(title) and not pattern.search(summary):
                    continue

                dedupe_key = entry.get("id") or entry.get("link") or title
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                published = _extract_timestamp(entry)

                feed_type = _classify_feed(domain)

                record = ExploitRecord(
                    source="rss",
                    cve_id=cve_id,
                    title=title,
                    url=entry.get("link", ""),
                    published=published,
                    reliability=reliability,
                    metadata={
                        "feed_domain": domain,
                        "feed_type": feed_type,
                        "tags": entry.get("tags", []),
                    }
                )

                results.append(record)

    logger.info("RSS chatter results", count=len(results), cve=cve_id)
    return results


def _extract_domain(url: str) -> str:
    """Safe domain extraction."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host.split(".")[0].lower()


def _extract_summary(entry: dict) -> str:
    """Safe summary extraction."""
    if entry.get("summary"):
        return entry["summary"]
    if entry.get("description"):
        return entry["description"]
    content = entry.get("content")
    if isinstance(content, list) and content:
        return content[0].get("value", "")
    return ""


def _extract_timestamp(entry: dict) -> datetime:
    """Extract published/updated timestamps safely."""
    for key in ["published", "updated", "created", "pubDate"]:
        ts = entry.get(key)
        if ts:
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                continue
    return datetime.utcnow()


def _classify_feed(domain: str) -> str:
    """Classify feed type based on domain."""
    if domain in ["msrc", "cisco", "redhat", "ubuntu", "debian", "vmware"]:
        return "vendor"
    if domain in ["packetstormsecurity", "seclists", "attackerkb"]:
        return "exploit"
    return "news"
