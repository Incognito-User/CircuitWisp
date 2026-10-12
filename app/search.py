# app/search.py

from app.sources.kev import search_kev
from app.sources.epss import search_epss
from app.sources.nvd import search_nvd
from app.sources.exploitdb import search_exploitdb
from app.sources.metasploit import search_metasploit
from app.sources.github import search_github_pocs
from app.service import build_snapshot
from app.utils.logging import log_source_error


async def search_intel(query: str):
    """
    Dynamic multi-source CTI search.
    Queries KEV, EPSS, NVD, ExploitDB, Metasploit, GitHub PoCs,
    merges results, builds unified snapshots, and ranks by relevance.
    """

    query = query.strip()
    if not query:
        return {"query": query, "results": [], "count": 0}

    raw_results = []

    # --- 1. Query all sources ---
    try:
        raw_results += await search_kev(query)
    except Exception as exc:
        log_source_error("search", "kev", exc)

    try:
        raw_results += await search_epss(query)
    except Exception as exc:
        log_source_error("search", "epss", exc)

    try:
        raw_results += await search_nvd(query)
    except Exception as exc:
        log_source_error("search", "nvd", exc)

    try:
        raw_results += await search_exploitdb(query)
    except Exception as exc:
        log_source_error("search", "exploitdb", exc)

    try:
        raw_results += await search_metasploit(query)
    except Exception as exc:
        log_source_error("search", "metasploit", exc)

    try:
        raw_results += await search_github_pocs(query)
    except Exception as exc:
        log_source_error("search", "github", exc)

    # --- 2. Extract CVE IDs ---
    cve_ids = {r["cve_id"] for r in raw_results if r.get("cve_id")}

    # --- 3. Build unified snapshots ---
    snapshots = []
    for cve_id in cve_ids:
        try:
            snapshot = await build_snapshot(cve_id)
            snapshots.append(snapshot)
        except Exception as exc:
            log_source_error("search", cve_id, exc)

    # --- 4. Score relevance ---
    ranked = sorted(snapshots, key=lambda s: compute_relevance(s, query), reverse=True)

    return {
        "query": query,
        "results": ranked,
        "count": len(ranked)
    }


def compute_relevance(snapshot: dict, query: str) -> float:
    """
    Compute relevance score for search results.
    Factors:
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
