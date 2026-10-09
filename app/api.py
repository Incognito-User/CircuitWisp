from fastapi import APIRouter, HTTPException, Query
from typing import List

from app.service import (
    gather_exploits,
    diagnose_sources,
    build_snapshot,
    build_heat,
    heat_bulk,
    heat_compare,
)
from app.validation import validate_cve

router = APIRouter()


@router.get("/cve/{cve_id}")
async def get_cve_activity(cve_id: str):
    if not validate_cve(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE format")
    snapshot = await gather_exploits(cve_id)
    return snapshot.to_dict()


@router.get("/sources")
async def get_sources():
    return await diagnose_sources()


@router.get("/snapshot/{cve_id}")
async def get_snapshot(cve_id: str):
    if not validate_cve(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE format")
    return await build_snapshot(cve_id)


@router.get("/heat/{cve_id}")
async def get_heat(cve_id: str):
    if not validate_cve(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE format")
    return await build_heat(cve_id)


@router.post("/heat/bulk")
async def get_heat_bulk(cves: List[str]):
    invalid = [c for c in cves if not validate_cve(c)]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid CVE(s): {', '.join(invalid)}",
        )
    return await heat_bulk(cves)


@router.get("/heat/compare")
async def get_heat_compare(
    cve1: str = Query(...),
    cve2: str = Query(...),
):
    if not validate_cve(cve1) or not validate_cve(cve2):
        raise HTTPException(status_code=400, detail="Invalid CVE format")
    return await heat_compare(cve1, cve2)
