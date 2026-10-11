# app/search.py

from typing import List, Dict, Any
from app.service import build_snapshot
from app.utils.logging import log_source_error

# For now, we search across CVE IDs in a watchlist.
# Later, you can expand this to advisories, exploits, vendor bulletins, etc.
SEARCH_INDEX = [
    "CVE-2021-44228",
    "CVE-2020-1472",
    "CVE-2019-0708",
    "CVE-2017-0144",
    "CVE-2023-34362"
]


async def search_intel(query: str) -> Dict[str, Any]:
    """
    Basic search across known CVEs.
    - Matches CVE IDs containing the query
    - Returns snapshot + simple relevance score
    """

    query = query.strip()
    if not query:
        return {
            "query": query,
            "results": [],
            "count": 0
        }

    matches: List[str] = []

    # Simple matching: case-insensitive substring on CVE IDs
    for cve_id in SEARCH_INDEX:
        if query.lower() in cve_id.lower():
            matches.append(cve_id)

    results = []

    for cve_id in matches:
        try:
            snapshot = await build_snapshot(cve_id)
        except Exception as exc:
            log_source_error("search", cve_id, exc)
            continue

        # Simple relevance scoring: exact match > partial
        relevance = 1.0 if query.upper() == cve_id.upper() else 0.7

        results.append({
            "cve_id": cve_id,
            "relevance": relevance,
            "snapshot": snapshot
        })

    # Sort by relevance
    results.sort(key=lambda x: x["relevance"], reverse=True)

    return {
        "query": query,
        "results": results,
        "count": len(results)
    }
