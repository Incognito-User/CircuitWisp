import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cve/2.0/"


async def fetch_nvd(cve_id: str) -> Dict[str, Any]:
    """
    Fetch NVD data for a CVE.
    Returns a dict with keys like: description, cvss_v3, etc.
    """

    url = f"{NVD_URL}{cve_id}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning(f"NVD fetch failed for {cve_id}: {exc}")
        return {}

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return {}

    v = vulns[0]
    cve = v.get("cve", {})
    descriptions = cve.get("descriptions") or []
    desc = descriptions[0]["value"] if descriptions else ""

    metrics = v.get("cve", {}).get("metrics", {})
    cvss_v3 = 0.0

    for key, val in metrics.items():
        if isinstance(val, list) and val:
            metric = val[0]
            cvss_v3 = float(metric.get("cvssData", {}).get("baseScore", 0.0))
            break

    return {
        "description": desc,
        "cvss_v3": cvss_v3,
    }
