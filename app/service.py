from typing import List
import asyncio
from datetime import datetime
from app.scoring import risk_level

from sources.exploitdb import fetch_exploitdb
from sources.github import fetch_github
from sources.metasploit import fetch_metasploit
from sources.vendor import fetch_vendor_advisories
from sources.rss import fetch_rss_chatter, RSS_FEEDS, SOURCE_RELIABILITY, RSS_CACHE

from app.models import ExploitRecord
from app.scoring import score_exploit
from app.scoring import (
    exploit_maturity,
    vendor_confirmed,
    poc_available,
    heat_score,
)


class ExploitActivitySnapshot:
    """
    Unified view of exploit activity for a given CVE.
    Contains scored records and simple aggregate metrics.
    """

    def __init__(self, cve_id: str, records: List[ExploitRecord]):
        self.cve_id = cve_id
        self.records = records
        self.total = len(records)
        self.by_source = self._group_by_source()

    def _group_by_source(self) -> dict:
        counts: dict[str, int] = {}
        for r in self.records:
            src = r.source.lower()
            counts[src] = counts.get(src, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "total": self.total,
            "by_source": self.by_source,
            "records": [
                {
                    "source": r.source,
                    "cve_id": r.cve_id,
                    "title": r.title,
                    "url": r.url,
                    "published": r.published.isoformat(),
                    "score": score_exploit(r),
                }
                for r in self.records
            ],
        }


async def gather_exploits(cve_id: str) -> ExploitActivitySnapshot:
    """
    Fetch and correlate exploits across all sources for a CVE,
    score them, and return a unified activity snapshot.
    """

    # Run all sources concurrently
    edb_task = fetch_exploitdb(cve_id)
    gh_task = fetch_github(cve_id)
    ms_task = fetch_metasploit(cve_id)
    vendor_task = fetch_vendor_advisories(cve_id)
    rss_task = fetch_rss_chatter(cve_id)

    edb, gh, ms, vendor, rss = await asyncio.gather(
        edb_task, gh_task, ms_task, vendor_task, rss_task
    )

    # Merge all records
    records: List[ExploitRecord] = []
    records.extend(edb)
    records.extend(gh)
    records.extend(ms)
    records.extend(vendor)
    records.extend(rss)

    # Sort by score (desc) then recency
    records.sort(
        key=lambda r: (score_exploit(r), r.published),
        reverse=True,
    )

    return ExploitActivitySnapshot(cve_id=cve_id, records=records)


# ---------------------------------------------------------------------------
# /sources diagnostic endpoint service
# ---------------------------------------------------------------------------

async def diagnose_sources() -> list[dict]:
    """
    Return diagnostic information about RSS feed health, caching, and reliability.
    """

    results = []

    for feed_url in RSS_FEEDS:
        domain = feed_url.split("//")[1].split("/")[0].split(".")[0]
        reliability = SOURCE_RELIABILITY.get(domain, 0.5)

        cached = RSS_CACHE.get(feed_url)

        results.append({
            "name": domain,
            "url": feed_url,
            "reliability": reliability,
            "success": cached is not None,
            "latency_ms": cached.get("latency_ms") if cached else None,
            "cache_hit": cached is not None,
            "error": cached.get("error") if cached else None,
            "entries": len(cached["parsed"].entries) if cached else 0,
        })

    return results


# ---------------------------------------------------------------------------
# /snapshot/{cve_id} endpoint service
# ---------------------------------------------------------------------------

async def build_snapshot(cve_id: str) -> dict:
    """
    Build a unified CVE snapshot containing all exploit intelligence sources.
    """

    snapshot = await gather_exploits(cve_id)
    records = snapshot.records

    summary = {
        "total_records": len(records),
        "sources_used": len(set(r.source for r in records)),
        "highest_reliability": max((r.reliability for r in records), default=0),
        "earliest": min((r.published for r in records), default=None),
        "latest": max((r.published for r in records), default=None),
    }

    return {
        "cve_id": cve_id,
        "total_records": summary["total_records"],
        "sources_used": summary["sources_used"],
        "records": [r.dict() for r in records],
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# /heat/{cve_id} endpoint service
# ---------------------------------------------------------------------------

async def build_heat(cve_id: str) -> dict:
    """
    Build a unified heat score for a CVE using exploit maturity,
    vendor confirmation, PoC availability, chatter volume, and recency.
    """

    snapshot = await gather_exploits(cve_id)
    records = snapshot.records

    # Core components
    maturity = exploit_maturity(records)
    vendor_conf = vendor_confirmed(records)
    poc = poc_available(records)

    # Chatter volume (RSS)
    chatter_count = sum(1 for r in records if r.source.lower() == "rss")

    # Recency
    latest_published = max((r.published for r in records), default=None)

    # Final heat score
    score = heat_score(
        exploit_maturity=maturity,
        poc_available=poc,
        vendor_confirmed=vendor_conf,
        chatter_count=chatter_count,
        latest_published=latest_published,
    )

    # Human-readable explanation of why the score is what it is
    breakdown = {
        "exploit_maturity": (
            "High exploit maturity (weaponized or actively exploited)"
            if maturity >= 0.6 else
            "Moderate exploit maturity (PoCs exist)"
            if maturity >= 0.3 else
            "Low exploit maturity (no PoCs or weaponization detected)"
        ),
        "poc_available": (
            "Proof-of-concept available (GitHub, ExploitDB, or Metasploit)"
            if poc else
            "No public proof-of-concept available"
        ),
        "vendor_confirmation": (
            "Vendor has acknowledged or confirmed the vulnerability"
            if vendor_conf else
            "No vendor confirmation detected"
        ),
        "chatter": (
            f"High exploit chatter ({chatter_count} RSS mentions)"
            if chatter_count > 10 else
            f"Moderate exploit chatter ({chatter_count} RSS mentions)"
            if chatter_count > 3 else
            f"Low exploit chatter ({chatter_count} RSS mentions)"
            if chatter_count > 0 else
            "No exploit chatter detected"
        ),
        "recency": (
            "Recent activity within the last 7 days"
            if latest_published and (datetime.utcnow() - latest_published).days <= 7 else
            "Activity within the last 30 days"
            if latest_published and (datetime.utcnow() - latest_published).days <= 30 else
            "Older activity"
            if latest_published else
            "No activity timestamp available"
        ),
    }

    return {
        "cve_id": cve_id,
        "heat_score": score,
        "risk_level": risk_level(score),
        "exploit_maturity": maturity,
        "poc_available": poc,
        "vendor_confirmed": vendor_conf,
        "chatter_count": chatter_count,
        "latest_published": latest_published.isoformat() if latest_published else None,
        "breakdown": breakdown,
    }
