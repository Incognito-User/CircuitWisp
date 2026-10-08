import httpx
import logging
from datetime import datetime

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

VENDOR_ENDPOINTS = {
    "microsoft": "https://api.msrc.microsoft.com/cvrf/v2.0/cve/",
    "cisco": "https://example-cisco-api/cve/",
}


async def fetch_vendor_advisories(cve_id: str) -> list[ExploitRecord]:
    results: list[ExploitRecord] = []

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        for vendor, base_url in VENDOR_ENDPOINTS.items():
            try:
                resp = await client.get(f"{base_url}{cve_id}")
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPError:
                logger.warning("Vendor advisory fetch failed", vendor=vendor, cve=cve_id)
                continue

            record = ExploitRecord(
                source="vendor",
                cve_id=cve_id,
                title=f"{vendor} advisory for {cve_id}",
                url=data.get("document_url", ""),
                published=datetime.utcnow(),  # refine with real field
                reliability=0.9,
            )
            results.append(record)

    return results
