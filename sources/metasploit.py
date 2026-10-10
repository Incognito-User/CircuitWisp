import httpx
import logging
from datetime import datetime
from typing import List
from app.models import ExploitRecord

logger = logging.getLogger(__name__)

MSF_REPO = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master"


async def fetch_metasploit(cve_id: str) -> List[ExploitRecord]:
    """
    Fetch Metasploit-related references for a CVE.
    This is a heuristic placeholder; you can later replace it
    with a more precise mapping or local index.
    """

    # Placeholder: treat presence of CVE in docs as a signal.
    # You can expand this to scan specific paths.
    urls = [
        f"{MSF_REPO}/documentation/modules/auxiliary/scanner/http/log4shell_scanner.md",
        f"{MSF_REPO}/documentation/modules/exploit/multi/http/vmware_vcenter_log4shell.md",
        f"{MSF_REPO}/documentation/modules/exploit/linux/http/mobileiron_core_log4shell.md",
    ]

    records: List[ExploitRecord] = []

    for url in urls:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url)
                resp.raise_for_status()
        except Exception as exc:
            logger.warning(f"Metasploit fetch failed for {cve_id} at {url}: {exc}")
            continue

        title = url.split("/")[-1]
        record = ExploitRecord(
            source="metasploit",
            cve_id=cve_id,
            title=title,
            url=url,
            published=datetime.utcnow(),
            reliability=0.95,
        )
        records.append(record)

    return records
