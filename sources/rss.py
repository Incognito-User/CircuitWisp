import logging
from datetime import datetime

import httpx
import feedparser

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

RSS_FEEDS = [
    "https://example.com/exploit-chatter.rss",
]


async def fetch_rss_chatter(cve_id: str) -> list[ExploitRecord]:
    results: list[ExploitRecord] = []

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        for feed_url in RSS_FEEDS:
            try:
                resp = await client.get(feed_url)
                resp.raise_for_status()
                parsed = feedparser.parse(resp.text)
            except httpx.HTTPError:
                logger.warning(f"RSS fetch failed for feed: {feed_url}")
                continue

            for entry in parsed.entries:
                title = entry.get("title", "")
                summary = entry.get("summary", "")
                if cve_id.upper() not in (title + summary).upper():
                    continue

                published = datetime.utcnow()
                record = ExploitRecord(
                    source="rss",
                    cve_id=cve_id,
                    title=title,
                    url=entry.get("link", ""),
                    published=published,
                    reliability=0.6,
                )
                results.append(record)

    logger.info("RSS chatter results", count=len(results), cve=cve_id)
    return results
