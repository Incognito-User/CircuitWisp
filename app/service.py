from typing import List
import asyncio
from datetime import datetime

# Ingestion modules (all hardened previously)
from sources.exploitdb import fetch_exploitdb
from sources.github import fetch_github
from sources.metasploit import fetch_metasploit
from sources.vendor import fetch_vendor_advisories
from sources.rss import fetch_rss_chatter, RSS_FEEDS, SOURCE_RELIABILITY, RSS_CACHE

from app.models import ExploitRecord
from app.scoring import (
    score_exploit,
    exploit_maturity,
    vendor_confirmed,
    poc_available,
    heat_score,
    risk_level,
)


# ---------------------------------------------------------------------------
# Exploit Activity Snapshot (core correlation object)
# ---------------------------------------------------------------------------

class ExploitActivitySnapshot:
    """
    Unified view of exploit activity for a given CVE.
    Contains scored records and simple aggregate metrics.

    Hardened:
    - deterministic grouping
    - safe iteration
    - no assumptions about record completeness
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
        """
        Convert snapshot to a safe JSON‑serializable dict.
        """
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


# ---------------------------------------------------------------------------
# Core ingestion aggregator
# ---------------------------------------------------------------------------

async def gather_exploits(cve_id: str) -> ExploitActivitySnapshot:
    """
    Fetch and correlate exploits across all sources for a CVE.

    Hardened:
    - concurrent ingestion
    - safe merging
    - deterministic sorting
    """

    edb_task = fetch_exploitdb(cve_id)
    gh_task = fetch_github(cve_id)
    ms_task = fetch_metasploit(cve_id)
    vendor_task = fetch_vendor_advisories(cve_id)
    rss_task = fetch_rss_chatter(cve_id)

    edb, gh, ms, vendor, rss = await asyncio.gather(
        edb_task, gh_task, ms_task, vendor_task, rss_task
    )

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

    Hardened:
    - safe cache access
    - safe parsed entry counting
    - no missing‑key errors
    """

    results = []

    for feed_url in RSS_FEEDS:
        domain = feed_url.split("//")[1].split("/")[0].split(".")[0]
        reliability = SOURCE_RELIABILITY.get(domain, 0.5)

        cached = RSS_CACHE.get(feed_url)
        parsed = cached.get("parsed") if cached else None
        entries = len(getattr(parsed, "entries", [])) if parsed else 0

        results.append({
            "name": domain,
            "url": feed_url,
            "reliability": reliability,
            "success": cached is not None,
            "latency_ms": cached.get("latency_ms") if cached else None,
            "cache_hit": cached is not None,
            "error": cached.get("error") if cached else None,
            "entries": entries,
        })

    return results


# ---------------------------------------------------------------------------
# /snapshot/{cve_id}
# ---------------------------------------------------------------------------

async def build_snapshot(cve_id: str) -> dict:
    """
    Build a unified CVE snapshot containing all exploit intelligence sources.

    Hardened:
    - safe min/max operations
    - safe summary construction
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
# /heat/{cve_id}
# ---------------------------------------------------------------------------

async def build_heat(cve_id: str) -> dict:
    """
    Build a unified heat score for a CVE using exploit maturity,
    vendor confirmation, PoC availability, chatter volume, and recency.

    Hardened:
    - safe timestamp handling
    - safe chatter counting
    - deterministic scoring
    """

    snapshot = await gather_exploits(cve_id)
    records = snapshot.records

    maturity = exploit_maturity(records)
    vendor_conf = vendor_confirmed(records)
    poc = poc_available(records)
    chatter_count = sum(1 for r in records if r.source.lower() == "rss")
    latest_published = max((r.published for r in records), default=None)

    score = heat_score(
        exploit_maturity=maturity,
        poc_available=poc,
        vendor_confirmed=vendor_conf,
        chatter_count=chatter_count,
        latest_published=latest_published,
    )

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


# ---------------------------------------------------------------------------
# Bulk heat scoring
# ---------------------------------------------------------------------------

async def heat_bulk(cve_ids: list[str]) -> list[dict]:
    """
    Bulk heat scoring for multiple CVEs.

    Hardened:
    - safe iteration
    - deterministic sorting
    """

    results: list[dict] = []

    for cve in cve_ids:
        heat = await build_heat(cve)
        results.append(heat)

    results.sort(key=lambda h: h.get("heat_score", 0), reverse=True)
    return results


# ---------------------------------------------------------------------------
# /heat/top — hardened
# ---------------------------------------------------------------------------

async def heat_top(cve_ids: list[str], limit: int = 10) -> list[dict]:
    """
    Return top-N CVEs by heat score.

    Hardened:
    - limit capped to 50
    - cve_ids capped to 200
    - deterministic sorting
    """

    limit = max(1, min(limit, 50))
    cve_ids = cve_ids[:200]

    results = await heat_bulk(cve_ids)
    return results[:limit]


# ---------------------------------------------------------------------------
# /heat/trending — hardened
# ---------------------------------------------------------------------------

async def heat_trending(cve_ids: list[str], limit: int = 10) -> list[dict]:
    """
    Return top-N trending CVEs.

    Trending = chatter + recency + heat_score.

    Hardened:
    - limit capped to 50
    - cve_ids capped to 200
    - deterministic multi-key sorting
    """

    limit = max(1, min(limit, 50))
    cve_ids = cve_ids[:200]

    results: list[dict] = []

    for cve in cve_ids:
        heat = await build_heat(cve)
        results.append(heat)

    results.sort(
        key=lambda h: (
            h.get("chatter_count", 0),
            h.get("latest_published") or "",
            h.get("heat_score", 0),
        ),
        reverse=True,
    )

    return results[:limit]


# ---------------------------------------------------------------------------
# /heat/compare
# ---------------------------------------------------------------------------

async def heat_compare(cve1: str, cve2: str) -> dict:
    """
    Side-by-side comparison of two CVEs.

    Hardened:
    - deterministic output
    - safe delta calculation
    """

    h1 = await build_heat(cve1)
    h2 = await build_heat(cve2)

    return {
        "cve1": h1["cve_id"],
        "cve2": h2["cve_id"],
        "cve1_heat": h1["heat_score"],
        "cve2_heat": h2["heat_score"],
        "cve1_risk": h1["risk_level"],
        "cve2_risk": h2["risk_level"],
        "delta_heat": h1["heat_score"] - h2["heat_score"],
        "details": {
            "cve1": h1,
            "cve2": h2,
        },
    }


# ---------------------------------------------------------------------------
# /attack_surface — hardened
# ---------------------------------------------------------------------------

async def attack_surface(asset: str, products: list[str], limit: int = 20) -> dict:
    """
    Map an asset to CVEs via its products/services.

    Hardened:
    - asset name sanitized
    - products list bounded
    - limit bounded
    - no SSRF or dynamic URL construction
    - safe heuristic mapping (placeholder for future CPE/SBOM integration)
    """

    asset = asset.strip().lower()
    limit = max(1, min(limit, 50))
    products = products[:50]

    # Placeholder safe mapping (no external calls)
    cve_candidates: list[str] = []

    for product in products:
        product = product.strip().lower()
        if not product:
            continue

        if "openssl" in product:
            cve_candidates.extend(["CVE-2023-0464", "CVE-2022-0778"])
        elif "apache" in product:
            cve_candidates.extend(["CVE-2023-25690", "CVE-2021-41773"])
        elif "nginx" in product:
            cve_candidates.extend(["CVE-2022-41741", "CVE-2021-23017"])
        elif "windows" in product:
            cve_candidates.extend(["CVE-2024-30080", "CVE-2024-30078"])

    cve_candidates = list(set(cve_candidates))[:200]

    results: list[dict] = []
    for cve in cve_candidates:
        heat = await build_heat(cve)
        results.append(heat)

    results.sort(key=lambda h: h.get("heat_score", 0), reverse=True)

    return {
        "asset": asset,
        "products": products,
        "total_cves": len(results),
        "top_cves": results[:limit],
    }
# ---------------------------------------------------------------------------
# /timeline/{cve_id} — hardened
# ---------------------------------------------------------------------------

async def build_timeline(cve_id: str) -> dict:
    """
    Build a chronological exploit evolution timeline for a CVE.

    Hardened:
    - safe timestamp normalization
    - bounded event count
    - deterministic sorting
    - no SSRF or dynamic URL construction
    """

    snapshot = await gather_exploits(cve_id)
    records = snapshot.records

    # Normalize timestamps (fallback to now)
    events = []
    for r in records:
        ts = r.published or datetime.utcnow()

        events.append({
            "timestamp": ts.isoformat(),
            "source": r.source,
            "title": r.title,
            "url": r.url,
            "reliability": r.reliability,
            "score": score_exploit(r),
            "metadata": {
                "is_poc": r.source.lower() in {"github", "exploitdb", "metasploit"},
                "is_vendor": r.source.lower() in {
                    "vendor", "msrc", "cisco", "redhat", "ubuntu", "debian", "vmware"
                },
                "is_chatter": r.source.lower() == "rss",
            }
        })

    # Sort chronologically
    events.sort(key=lambda e: e["timestamp"])

    # Bound output (OWASP A05: prevent unbounded responses)
    events = events[:500]

    # Timeline summary
    first_seen = events[0]["timestamp"] if events else None
    last_seen = events[-1]["timestamp"] if events else None

    return {
        "cve_id": cve_id,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "total_events": len(events),
        "timeline": events,
    }
