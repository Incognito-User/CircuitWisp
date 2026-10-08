from fastapi import APIRouter
from app.service import gather_exploits, diagnose_sources, build_snapshot

router = APIRouter()


@router.get("/cve/{cve_id}")
async def get_cve_activity(cve_id: str):
    """
    Existing endpoint: unified exploit activity snapshot for a CVE.
    """
    snapshot = await gather_exploits(cve_id)
    return snapshot.to_dict()


@router.get("/sources")
async def get_sources():
    """
    Diagnostic endpoint: health, cache status, reliability, and entry counts
    for all RSS feeds.
    """
    return await diagnose_sources()


@router.get("/snapshot/{cve_id}")
async def get_snapshot(cve_id: str):
    """
    CVE fusion endpoint: returns enriched, merged intelligence from all sources.
    """
    return await build_snapshot(cve_id)
