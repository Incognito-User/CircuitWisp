# app/api.py

from fastapi import APIRouter
from .config import config_status
from .service import build_snapshot, build_timeline


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

    async def get_config_status(self):
        """
        Returns configuration status, including which API keys are loaded.
        """
        return config_status()

    async def get_cve_snapshot(self, cve_id: str):
        """
        Returns the full CircuitWisp snapshot for a given CVE.
        """
        return await build_snapshot(cve_id)

    async def get_cve_timeline(self, cve_id: str):
        """
        Returns the timeline of events for a given CVE.
        """
        return await build_timeline(cve_id)


# Export router instance for main.py
router = Router()
