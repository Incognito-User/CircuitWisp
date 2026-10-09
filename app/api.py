from fastapi import APIRouter
from app.service import build_snapshot, build_timeline

router = APIRouter()

@router.get("/cve/{cve_id}")
async def get_cve_snapshot(cve_id: str):
    return await build_snapshot(cve_id)

@router.get("/timeline/{cve_id}")
async def get_cve_timeline(cve_id: str):
    return await build_timeline(cve_id)
