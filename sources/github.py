import httpx
import logging
from datetime import datetime
from typing import List
from app.models import ExploitRecord

logger = logging.getLogger(__name__)

SEARCH_URL = "https://api.github.com/search/code"


async def fetch_github(cve_id: str) -> List[ExploitRecord]:
    """
    Fetch GitHub code/search results for a CVE.
    Returns a list of ExploitRecord objects.
    """

    params = {
        "q": f"{cve_id} in:file",
        "per_page": 20,
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(SEARCH_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning(f"GitHub search failed for {cve_id}: {exc}")
        return []

    items = data.get("items", [])
    records: List[ExploitRecord] = []

    for item in items:
        html_url = item.get("html_url")
        repo = item.get("repository", {}) if isinstance(item.get("repository"), dict) else {}
        name = repo.get("full_name") or item.get("name") or "GitHub result"

        record = ExploitRecord(
            source="github",
            cve_id=cve_id,
            title=name,
            url=html_url,
            published=datetime.utcnow(),
            reliability=0.7,
        )
        records.append(record)

    return records
