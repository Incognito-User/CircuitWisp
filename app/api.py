from fastapi import APIRouter, HTTPException, Query
from typing import List
import re

from app.service import (
    gather_exploits,
    diagnose_sources,
    build_snapshot,
    build_heat,
    heat_bulk,
    heat_compare,
    build_timeline,
    build_actors,
)


# ---------------------------------------------------------------------------
# CVE Validation (OWASP A03: Injection Prevention)
# ---------------------------------------------------------------------------

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")

def validate_cve(cve_id: str) -> bool:
    return bool(CVE_PATTERN.match(cve_id))


router = APIRouter()

# ---------------------------------------------------------------------------
# /timeline/{cve_id} — hardened
# ---------------------------------------------------------------------------

@router.get("/timeline/{cve_id}")
async def api_timeline(cve_id: str):
    """
    Hardened timeline endpoint:
    - strict CVE validation (OWASP A03)
    - safe chronological ordering
    - bounded output (OWASP A05)
    - no SSRF or dynamic URL construction (OWASP A10)
    """

    if not validate_cve(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE format")

    return await build_timeline(cve_id)


# ---------------------------------------------------------------------------
# /cve/{cve_id}
# ---------------------------------------------------------------------------

@router.get("/cve/{cve_id}")
async def get_cve_activity(cve_id: str):
    if not validate_cve(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE format")
    snapshot = await gather_exploits(cve_id)
    return snapshot.to_dict()


# ---------------------------------------------------------------------------
# /sources
# ---------------------------------------------------------------------------

@router.get("/sources")
async def get_sources():
    return await diagnose_sources()


# ---------------------------------------------------------------------------
# /snapshot/{cve_id}
# ---------------------------------------------------------------------------

@router.get("/snapshot/{cve_id}")
async def get_snapshot(cve_id: str):
    if not validate_cve(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE format")
    return await build_snapshot(cve_id)


# ---------------------------------------------------------------------------
# /heat/{cve_id}
# ---------------------------------------------------------------------------

@router.get("/heat/{cve_id}")
async def get_heat(cve_id: str):
    if not validate_cve(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE format")
    return await build_heat(cve_id)


# ---------------------------------------------------------------------------
# /heat/bulk
# ---------------------------------------------------------------------------

@router.post("/heat/bulk")
async def get_heat_bulk(cves: List[str]):
    invalid = [c for c in cves if not validate_cve(c)]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid CVE(s): {', '.join(invalid)}",
        )
    return await heat_bulk(cves)


# ---------------------------------------------------------------------------
# /heat/compare
# ---------------------------------------------------------------------------

@router.get("/heat/compare")
async def get_heat_compare(
    cve1: str = Query(...),
    cve2: str = Query(...),
):
    if not validate_cve(cve1) or not validate_cve(cve2):
        raise HTTPException(status_code=400, detail="Invalid CVE format")
    return await heat_compare(cve1, cve2)

# ---------------------------------------------------------------------------
# /actors/{cve_id} — hardened
# ---------------------------------------------------------------------------

@router.get("/actors/{cve_id}")
async def api_actors(cve_id: str):
    """
    Threat actor interest for a CVE.

    Hardened:
    - strict CVE validation (OWASP A03)
    - bounded actor list
    - heuristic-only, no external actor DB calls yet
    """

    if not validate_cve(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE format")

    return await build_actors(cve_id)
