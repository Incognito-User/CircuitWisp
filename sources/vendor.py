import httpx
import logging
from datetime import datetime
from typing import List
from app.models import ExploitRecord

logger = logging.getLogger(__name__)

MSRC_URL = "https://api.msrc.microsoft.com/cvrf/v2.0/cve/"
CISCO_URL = "https://sec.cloudapps.cisco.com/security/center/search.x"
DEBIAN_RSS = "https://www.debian.org/security/dsa.atom"


async def fetch_vendor_advisories(cve_id: str) -> List[ExploitRecord]:
    """
    Fetch vendor advisories (MSRC, Cisco, Debian, etc.) for a CVE.
    Returns a list of ExploitRecord objects tagged as vendor sources.
    """

    records: List[ExploitRecord] = []

    # MSRC
    msrc_url = f"{MSRC_URL}{cve_id}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(msrc_url)
            resp.raise_for_status()
        records.append(
            ExploitRecord(
                source="msrc",
                cve_id=cve_id,
                title=f"MSRC advisory for {cve_id}",
                url=msrc_url,
                published=datetime.utcnow(),
                reliability=0.8,
            )
        )
    except Exception as exc:
        logger.warning(f"MSRC advisory fetch failed for {cve_id}: {exc}")

    # Cisco
    cisco_params = {"keyword": cve_id}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(CISCO_URL, params=cisco_params)
            resp.raise_for_status()
        records.append(
            ExploitRecord(
                source="cisco",
                cve_id=cve_id,
                title=f"Cisco advisory search for {cve_id}",
                url=f"{CISCO_URL}?keyword={cve_id}",
                published=datetime.utcnow(),
                reliability=0.8,
            )
        )
    except Exception as exc:
        logger.warning(f"Cisco advisory fetch failed for {cve_id}: {exc}")

    # Debian RSS (generic)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(DEBIAN_RSS)
            resp.raise_for_status()
        records.append(
            ExploitRecord(
                source="debian",
                cve_id=cve_id,
                title="Debian security RSS feed",
                url=DEBIAN_RSS,
                published=datetime.utcnow(),
                reliability=0.7,
            )
        )
    except Exception as exc:
        logger.warning(f"Debian RSS fetch failed for {cve_id}: {exc}")

    return records
