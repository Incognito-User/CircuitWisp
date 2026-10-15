# app/sources/nvd.py
# ---------------------------------------------------------------------------
# NVD CVE DETAILS (API v2)
# ---------------------------------------------------------------------------

import os
import httpx
import logging
import asyncio

logger = logging.getLogger(__name__)

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cve/2.0"

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/118.0.0.0 Safari/537.36"
    )
}


async def _nvd_request(client, params):
    """
    Internal helper: performs NVD request with retry logic for 429.
    """

    # NVD requires apiKey in HEADERS, not params
    headers = {
        "apiKey": NVD_API_KEY,
        **BROWSER_HEADERS
    }

    resp = await client.get(NVD_URL, params=params, headers=headers)

    # Handle rate limiting (429 Too Many Requests)
    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", 5))
        logger.warning(f"NVD rate limited (429). Retrying after {retry_after}s...")
        await asyncio.sleep(retry_after)
        resp = await client.get(NVD_URL, params=params, headers=headers)

    return resp


async def fetch_nvd(cve_id: str):
    params = {"cveId": cve_id}

    try:
        async with httpx.AsyncClient(
            timeout=20,
            follow_redirects=True,
        ) as client:

            resp = await _nvd_request(client, params)

            if resp.status_code != 200:
                logger.warning(f"NVD fetch failed: {resp.status_code} {resp.text[:200]}")
                return {}

            data = resp.json()

    except Exception as exc:
        logger.warning(f"NVD fetch failed: {exc}")
        return {}

    try:
        vuln = data["vulnerabilities"][0]["cve"]
    except Exception:
        return {}

    published = vuln.get("published")
    metrics = vuln.get("metrics", {})

    cvss_v3 = None
    if "cvssMetricV31" in metrics:
        cvss_v3 = metrics["cvssMetricV31"][0]["cvssData"]
    elif "cvssMetricV30" in metrics:
        cvss_v3 = metrics["cvssMetricV30"][0]["cvssData"]

    return {
        "cvss_v3": cvss_v3,
        "published": published,
    }


# ---------------------------------------------------------------------------
# Fetch recent CVEs (required by trending.py)
# ---------------------------------------------------------------------------
async def fetch_recent_cves(limit: int = 50):
    """
    Fetch recent CVEs from NVD (API v2).
    Returns a list of CVE IDs.
    """
    params = {"resultsPerPage": limit}

    try:
        async with httpx.AsyncClient(
            timeout=20,
            follow_redirects=True,
        ) as client:

            resp = await _nvd_request(client, params)

            if resp.status_code != 200:
                logger.warning(f"NVD recent fetch failed: {resp.status_code} {resp.text[:200]}")
                return []

            data = resp.json()

    except Exception as exc:
        logger.warning(f"NVD recent fetch failed: {exc}")
        return []

    results = []

    try:
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if cve_id:
                results.append(cve_id)

    except Exception as exc:
        logger.warning(f"Failed to parse NVD recent CVEs: {exc}")
        return []

    return results
