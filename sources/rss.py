import logging
import asyncio
import re
from datetime import datetime
from time import time

import httpx
import feedparser

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

# Concurrency limit
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

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# SOURCE RELIABILITY SCORING (CTI TRADECRAFT)
#
# These numeric reliability scores are based on standard Cyber Threat
# Intelligence (CTI) source evaluation practices. CTI teams typically use
# the classic intelligence model:
#
#   - Source Reliability (A–F)
#   - Information Credibility (1–6)
#
# Vendors often convert these into numeric values (0.0–1.0). The scores
# below reflect how authoritative, consistent, and close to exploitation
# each feed is:
#
#   1.0  - Vendor advisories (MSRC, Cisco, Red Hat, Ubuntu, Debian, VMware)
#          These are primary, authoritative sources publishing official CVEs,
#          patches, exploitation status, and security bulletins.
#
#   0.9–0.95 - Exploit/PoC feeds (PacketStorm, AttackerKB, Seclists)
#              High-signal sources close to real exploitation activity.
#              They frequently publish PoCs, exploit chatter, and technical
#              vulnerability discussions.
#
#   0.7–0.9 - Security news / research (Krebs, BleepingComputer, HackerNews,
#             SecurityWeek, DarkReading)
#             These are secondary editorial sources. They provide context,
#             early reporting, and analysis, but are not authoritative.
#
# These values can be tuned or expanded later, or replaced with a dynamic
# scoring engine that incorporates exploit maturity, vendor confirmation,
# PoC availability, and threat actor interest.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

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
            domain = feed_url.split("//")[1].split("/")[0].split(".")[0]
            reliability = SOURCE_RELIABILITY.get(domain, 0.5)

            try:
                # Check cache first
                cached = RSS_CACHE.get(feed_url)
                if cached and (time() - cached["timestamp"] < CACHE_TTL):
                    parsed = cached["parsed"]
                else:
                    # Limit ONLY the network request
                    async with SEM:
                        resp = await client.get(feed_url)
                        resp.raise_for_status()

                    parsed = feedparser.parse(resp.text)
                    RSS_CACHE[feed_url] = {"parsed": parsed, "timestamp": time()}

            except httpx.HTTPError:
                logger.warning(f"RSS fetch failed for feed: {feed_url}")
                continue

            for entry in parsed.entries:
                title = entry.get("title", "")
                summary = (
                    entry.get("summary")
                    or entry.get("description")
                    or entry.get("content", [{}])[0].get("value")
                    or ""
                )

                if not pattern.search(title) and not pattern.search(summary):
                    continue

                dedupe_key = (title, entry.get("link", ""))
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                published = datetime.utcnow()

                tags = entry.get("tags", [])
                feed_type = (
                    "vendor" if domain in ["msrc", "cisco", "redhat", "ubuntu", "debian", "vmware"]
                    else "exploit" if domain in ["packetstormsecurity", "seclists", "attackerkb"]
                    else "news"
                )

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
                        "tags": tags,
                    }
                )

                results.append(record)

    logger.info(f"RSS chatter results: count={len(results)}, cve={cve_id}")
    return results
