# app/api.py

from fastapi import APIRouter, Query
from app.search import search_intel
from app.service import build_snapshot

router = APIRouter()


# ---------------------------------------------------------
# Unified Search Endpoint
# ---------------------------------------------------------
@router.get("/search")
async def search_endpoint(
    q: str = Query(..., description="Search term (CVE ID, keyword, tool, actor, etc.)")
):
    """
    Unified multi-source CTI search.
    Queries KEV, EPSS, NVD, ExploitDB, Metasploit, GitHub PoCs,
    builds unified snapshots, and ranks results by relevance.
    """
    return await search_intel(q)


# ---------------------------------------------------------
# Advanced Search Endpoint
# ---------------------------------------------------------
@router.get("/search/advanced")
async def search_advanced(
    q: str = Query(...),
    include_snapshots: bool = Query(True),
    include_sources: bool = Query(False)
):
    """
    Advanced CTI search with optional snapshot and source metadata.
    Useful for dashboards and automation pipelines.
    """
    results = await search_intel(q)

    # Remove snapshots if requested
    if not include_snapshots:
        for r in results["results"]:
            r.pop("snapshot", None)

    # Add source metadata if requested
    if include_sources:
        results["sources"] = {
            "kev": True,
            "epss": True,
            "nvd": True,
            "exploitdb": True,
            "metasploit": True,
            "github": True
        }

    return results


# ---------------------------------------------------------
# Direct CVE Lookup
# ---------------------------------------------------------
@router.get("/search/{cve_id}")
async def search_single_cve(cve_id: str):
    """
    Direct CVE lookup using the snapshot engine.
    Returns full enriched CVE snapshot.
    """
    return await build_snapshot(cve_id)


# ---------------------------------------------------------
# Search Source Health Check
# ---------------------------------------------------------
@router.get("/search/sources")
async def search_sources_health():
    """
    Returns health status of search sources.
    Later you can make this dynamic.
    """
    return {
        "kev": "ok",
        "epss": "ok",
        "nvd": "ok",
        "exploitdb": "ok",
        "metasploit": "ok",
        "github": "ok"
    }
