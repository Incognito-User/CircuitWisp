# app/api.py
# ---------------------------------------------------------------------------
# FASTAPI ROUTER — PUBLIC API ENDPOINTS
# Provides:
#   - /snapshot/{cve_id}        → full enriched CVE snapshot
#   - /timeline/{cve_id}        → chronological CVE timeline
#   - /actors/{cve_id}          → actor + campaign + tooling enrichment
#   - /campaigns                → unified campaign feed (CISA + MITRE)
#   - /trending                 → daily trending CVEs
#   - /diagnostic/{cve_id}      → full pipeline test (snapshot + timeline + actors)
#   - /search/{cve_id}          → alias for snapshot
# ---------------------------------------------------------------------------

from fastapi import APIRouter, Query

# Core engines
from app.service import build_snapshot, build_timeline
from app.actors import get_actor_mapping, get_actor_by_name
from app.campaigns import get_all_campaigns
from app.trending import compute_trending

router = APIRouter()


# ---------------------------------------------------------------------------
# Snapshot (full intelligence)
# ---------------------------------------------------------------------------
@router.get("/snapshot/{cve_id}")
async def snapshot(cve_id: str):
    """
    Full enriched CVE snapshot including:
      - ExploitDB / GitHub / Metasploit
      - Vendor advisories
      - RSS chatter
      - EPSS / KEV / NVD
      - GreyNoise / Shodan
      - MITRE groups / CISA campaigns
      - Heat + risk level
      - SREI scoring
    """
    return await build_snapshot(cve_id)


# ---------------------------------------------------------------------------
# Search alias → snapshot
# ---------------------------------------------------------------------------
@router.get("/search/{cve_id}")
async def search_single_cve(cve_id: str):
    return await build_snapshot(cve_id)


@router.get("/search")
async def search_query(q: str = Query(..., description="CVE ID or keyword")):
    return await build_snapshot(q)


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------
@router.get("/timeline/{cve_id}")
async def timeline(cve_id: str):
    """
    Chronological CVE timeline:
      - Exploit publication
      - PoCs
      - Vendor advisories
      - RSS chatter
      - KEV/NVD timestamps
    """
    return await build_timeline(cve_id)


# ---------------------------------------------------------------------------
# Actor Intelligence
# ---------------------------------------------------------------------------
@router.get("/actors/{cve_id}")
async def actors(cve_id: str):
    """
    Actor intelligence for a CVE:
      - MITRE intrusion sets
      - CISA campaigns
      - Tooling associations
      - Actor heat score
    """
    return await get_actor_mapping(cve_id)


@router.get("/actor/{name}")
async def actor_detail(name: str):
    """
    Detailed actor profile:
      - Aliases
      - Techniques
      - Tools
      - Related CVEs
    """
    return await get_actor_by_name(name)


# ---------------------------------------------------------------------------
# Campaign Intelligence
# ---------------------------------------------------------------------------
@router.get("/campaigns")
async def campaigns():
    """
    Unified campaign feed:
      - CISA alerts + campaigns
      - MITRE intrusion sets
    """
    return await get_all_campaigns()


# ---------------------------------------------------------------------------
# Trending CVEs
# ---------------------------------------------------------------------------
@router.get("/trending")
async def trending():
    """
    Trending CVEs based on:
      - Multi-source recent discovery
      - Daily deltas
      - SREI priority scoring
    """
    return await compute_trending()


# ---------------------------------------------------------------------------
# Diagnostic — test ALL modules at once
# ---------------------------------------------------------------------------
@router.get("/diagnostic/{cve_id}")
async def diagnostic(cve_id: str):
    """
    Full pipeline diagnostic:
      - snapshot (full intelligence)
      - timeline (chronology)
      - actors (MITRE + CISA + tooling)
      - trending (global context)
    """
    snapshot = await build_snapshot(cve_id)
    timeline = await build_timeline(cve_id)
    actors = await get_actor_mapping(cve_id)
    trending = await compute_trending()

    return {
        "snapshot": snapshot,
        "timeline": timeline,
        "actors": actors,
        "trending": trending,
    }
