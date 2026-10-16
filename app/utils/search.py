# app/search.py
# ---------------------------------------------------------------------------
# SEARCH ENGINE — Unified multi-source CTI search
# Aggregates KEV, EPSS, NVD, ExploitDB, Metasploit, GitHub PoCs and builds
# enriched snapshots ranked by relevance.
# ---------------------------------------------------------------------------

from app.sources.nvd import fetch_nvd as search_nvd
from app.sources.epss import fetch_epss as search_epss
from app.sources.kev import fetch_kev as search_kev
from app.sources.exploitdb import fetch_exploitdb as search_exploitdb
from app.sources.metasploit import fetch_metasploit as search_metasploit
from app.sources.github import fetch_github as search_github_pocs

from app.service import build_snapshot
from app.utils.logging import log_source_error


# ---------------------------------------------------------------------------
# Unified Search Entry Point
# ---------------------------------------------------------------------------
async def search_intel(query: str):
    """
    Perform multi-source CTI search and return ranked snapshots.
    Safe with missing sources; errors logged but not propagated.
    """

    query = query.strip()
    if not query:
        return {"query": query, "results": [], "count": 0}

    raw_results = []

    # -----------------------------------------------------------------------
    # Normalize source results into list form
    # -----------------------------------------------------------------------
    def normalize(result):
        if not result:
            return []
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return [result]
        return []

    # -----------------------------------------------------------------------
    # Query all intelligence sources (safe error handling)
    # -----------------------------------------------------------------------
    try:
        raw_results += normalize(await search_kev(query))
    except Exception as exc:
        log_source_error("search", "kev", exc)

    try:
        raw_results += normalize(await search_epss(query))
    except Exception as exc:
        log_source_error("search", "epss", exc)

    try:
        raw_results += normalize(await search_nvd(query))
    except Exception as exc:
        log_source_error("search", "nvd", exc)

    try:
        raw_results += normalize(await search_exploitdb(query))
    except Exception as exc:
        log_source_error("search", "exploitdb", exc)

    try:
        raw_results += normalize(await search_metasploit(query))
    except Exception as exc:
        log_source_error("search", "metasploit", exc)

    try:
        raw_results += normalize(await search_github_pocs(query))
    except Exception as exc:
        log_source_error("search", "github", exc)

    # -----------------------------------------------------------------------
    # Extract unique CVE IDs
    # -----------------------------------------------------------------------
    cve_ids = {r["cve_id"] for r in raw_results if r.get("cve_id")}

    # -----------------------------------------------------------------------
    # Build unified snapshots for each CVE
    # -----------------------------------------------------------------------
    snapshots = []
    for cve_id in cve_ids:
        try:
            snapshot = await build_snapshot(cve_id)
            snapshots.append(snapshot)
        except Exception as exc:
            log_source_error("search", cve_id, exc)

    # -----------------------------------------------------------------------
    # Rank snapshots by relevance score
    # -----------------------------------------------------------------------
    ranked = sorted(snapshots, key=lambda s: compute_relevance(s, query), reverse=True)

    return {
        "query": query,
        "results": ranked,
        "count": len(ranked)
    }


# ---------------------------------------------------------------------------
# Relevance Scoring Model
# ---------------------------------------------------------------------------
def compute_relevance(snapshot: dict, query: str) -> float:
    """
    Compute relevance score using:
    - CVE ID match
    - Description match
    - Exploit availability
    - EPSS percentile
    - KEV status
    - Heat score
    """

    score = 0.0

    cve_id = snapshot.get("cve_id", "")
    description = snapshot.get("description", "")
    epss = snapshot.get("epss", {}).get("percentile", 0)
    exploits = len(snapshot.get("exploits", []))
    kev = snapshot.get("kev") is not None
    heat = snapshot.get("heat", 0)

    # Query match
    if query.lower() in cve_id.lower():
        score += 2.0
    if query.lower() in description.lower():
        score += 1.0

    # Exploit availability
    score += exploits * 1.5

    # EPSS percentile
    score += epss * 1.2

    # KEV status
    if kev:
        score += 3.0

    # Heat score
    score += heat * 0.5

    return score
