import httpx
import logging
from typing import Dict, Any, Optional

from app.config import settings

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def fetch_nvd(cve_id: str) -> Dict[str, Any]:
    """
    Fetch NVD CVE details (CVSS, CWE, etc.).

    Returns:
        {
            "cve": str,
            "cvss_v3": float | None,
            "cvss_v2": float | None,
            "cwe": str | None,
            "description": str | None,
        }
    """
    params = {"cveId": cve_id}

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        try:
            resp = await client.get(NVD_API, params=params)
            resp.raise_for_status()
        except Exception as exc:
            logger.warning(f"NVD fetch failed for {cve_id}: {exc}")
            return {
                "cve": cve_id,
                "cvss_v3": None,
                "cvss_v2": None,
                "cwe": None,
                "description": None,
            }

        try:
            data = resp.json()
        except Exception as exc:
            logger.warning(f"NVD returned non-JSON for {cve_id}: {exc}")
            return {
                "cve": cve_id,
                "cvss_v3": None,
                "cvss_v2": None,
                "cwe": None,
                "description": None,
            }

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {
            "cve": cve_id,
            "cvss_v3": None,
            "cvss_v2": None,
            "cwe": None,
            "description": None,
        }

    v = vulns[0].get("cve", {})
    metrics = vulns[0].get("cve", {}).get("metrics", {})

    cvss_v3 = None
    cvss_v2 = None

    # CVSS v3
    v3_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    if v3_list:
        cvss_v3 = v3_list[0].get("cvssData", {}).get("baseScore")

    # CVSS v2
    v2_list = metrics.get("cvssMetricV2") or []
    if v2_list:
        cvss_v2 = v2_list[0].get("cvssData", {}).get("baseScore")

    # CWE
    cwe = None
    problem_types = v.get("weaknesses", [])
    if problem_types:
        descs = problem_types[0].get("description", [])
        if descs:
            cwe = descs[0].get("value")

    # Description
    description = None
    descs = v.get("descriptions", [])
    if descs:
        description = descs[0].get("value")

    return {
        "cve": cve_id,
        "cvss_v3": cvss_v3,
        "cvss_v2": cvss_v2,
        "cwe": cwe,
        "description": description,
    }
