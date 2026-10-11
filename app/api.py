# app/api.py

from fastapi import APIRouter
from .config import config_status
from .service import build_snapshot, build_timeline
from .health import health_sources
from .scorebreakdown import score_breakdown
from app.trending import compute_trending
from app.actors import get_actor_mapping
from app.search import search_intel

class Router(APIRouter):
    def __init__(self):
        super().__init__()

        # Config endpoint
        self.add_api_route(
            "/config",
            self.get_config_status,
            methods=["GET"],
            tags=["config"]
        )

        # CVE snapshot endpoint
        self.add_api_route(
            "/cve/{cve_id}",
            self.get_cve_snapshot,
            methods=["GET"],
            tags=["cve"]
        )

        # CVE timeline endpoint
        self.add_api_route(
            "/timeline/{cve_id}",
            self.get_cve_timeline,
            methods=["GET"],
            tags=["timeline"]
        )

        # Health endpoint
        self.add_api_route(
            "/health/sources",
            self.get_health_sources,
            methods=["GET"],
            tags=["health"]
        )
        
        # Score breakdown endpoint
        self.add_api_route(
            "/scorebreakdown/{cve_id}",
            self.get_score_breakdown,
            methods=["GET"],
            tags=["score"]
        )
        
        # Trending endpoint
        self.add_api_route(
            "/trending",
            self.get_trending,
            methods=["GET"],
            tags=["intel"]
        )

        # Actors endpoint
        self.add_api_route(
            "/actors/{cve_id}",
            self.get_actors,
            methods=["GET"],
            tags=["intel"]
        )

        # Search endpoint
        self.add_api_route(
            "/search",
            self.search,
            methods=["GET"],
            tags=["intel"]
        )

    async def get_config_status(self):
        """Returns configuration status, including which API keys are loaded."""
        return config_status()

    async def get_cve_snapshot(self, cve_id: str):
        """Returns the full CircuitWisp snapshot for a given CVE."""
        return await build_snapshot(cve_id)

    async def get_cve_timeline(self, cve_id: str):
        """Returns the timeline of events for a given CVE."""
        return await build_timeline(cve_id)

    async def get_health_sources(self):
        """Returns real-time health status for all intel sources."""
        return await health_sources()

    async def get_score_breakdown(self, cve_id: str):
        """Returns a transparent, OWASP‑aligned breakdown of how the heat score was calculated."""
        return await score_breakdown(cve_id)

    async def get_trending(self):
        """Returns daily trending CVEs based on EPSS, KEV, and exploit activity."""
        return await compute_trending()

    async def get_actors(self, cve_id: str):
        """Returns threat actor associations for a given CVE."""
        return await get_actor_mapping(cve_id)

    async def search(self, q: str):
        """Searches across known CVEs and returns relevant snapshots."""
        return await search_intel(q)

# Export router instance for main.py
router = Router()
