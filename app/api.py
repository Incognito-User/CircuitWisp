from fastapi import FastAPI, APIRouter
from app.service import gather_exploits

app = FastAPI()
router = APIRouter()

@router.get("/cve/{cve_id}")
async def get_cve_activity(cve_id: str):
    snapshot = await gather_exploits(cve_id)
    return snapshot.to_dict()

app.include_router(router)
