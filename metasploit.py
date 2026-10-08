import httpx
import logging
from datetime import datetime

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

METASPLOIT_SEARCH_URL = "https://example-metasploit-api/search"  # placeholder


async def fetch_metasploit(cve_id: str) -> list[ExploitRecord]:
    params = {"q": cve_id}
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
            resp = await client.get(METASPLOIT_SEARCH_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        logger.error("Metasploit request failed", exc=str(exc), cve=cve_id)
        return []

    results: list[ExploitRecord] = []
    for mod in data.get("modules", []):
        record = ExploitRecord(
            source="metasploit",
            cve_id=cve_id,
            title=mod.get("name", "Metasploit module"),
            url=mod.get("reference", ""),
            published=datetime.utcnow(),  # or parse if available
            reliability=0.95,
        )
        results.append(record)

    return results
