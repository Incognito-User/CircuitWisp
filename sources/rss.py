import httpx
import logging
from datetime import datetime
from typing import List
from app.models import ExploitRecord

logger = logging.getLogger(__name__)

SECURITYWEEK_RSS = "https://feeds.securityweek.com/securityweek"


async def fetch_rss_chatter(cve_id: str) -> List[ExploitRecord]:
    """
    Fetch RSS-based chatter for a CVE (e.g., SecurityWeek).
    Returns a list of ExploitRecord objects with source 'rss'.
    """

    records: List[ExploitRecord] = []

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(SECURITYWEEK_RSS)
            resp.raise_for_status()
            text = resp.text
    except Exception as exc:
        logger.warning(f"RSS fetch failed for {cve_id}: {exc}")
        return []

    # Very simple heuristic: if CVE appears in feed text, treat as chatter.
    if cve_id in text:
        records.append(
            ExploitRecord(
                source="rss",
                cve_id=cve_id,
                title=f"RSS chatter mentioning {cve_id}",
                url=SECURITYWEEK_RSS,
                published=datetime.utcnow(),
                reliability=0.6,
            )
        )

    return records
