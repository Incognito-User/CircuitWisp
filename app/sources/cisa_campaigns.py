# app/sources/cisa_campaigns.py
# ---------------------------------------------------------------------------
# CISA Campaigns ingestion module
# ---------------------------------------------------------------------------

import httpx
import logging
import re
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

CISA_ALERTS_URL = "https://www.cisa.gov/sites/default/files/feeds/alerts.json"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def _fetch_json(url: str) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.warning("CISA campaigns fetch failed", extra={"url": url, "error": str(exc)})
        return {}


# ---------------------------------------------------------------------------
# Parse CISA Alerts →  extracts CVEs via regex
# ---------------------------------------------------------------------------
def parse_cisa_alerts(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = []

    alerts = data.get("alerts", [])
    for alert in alerts:
        try:
            # Extract CVEs from title + summary + link
            text = f"{alert.get('title','')} {alert.get('summary','')} {alert.get('link','')}"
            cve_matches = re.findall(r"CVE-\d{4}-\d+", text)

            results.append(
                {
                    "source": "cisa_alert",
                    "title": alert.get("title", "CISA Alert"),
                    "date": alert.get("date"),
                    "summary": alert.get("summary", ""),
                    "link": alert.get("link", ""),
                    "actors": alert.get("actors", []),
                    "cves": cve_matches,  # <-- FIXED
                }
            )
        except Exception as exc:
            logger.warning("Failed to parse CISA alert", extra={"error": str(exc), "raw": alert})

    return results


# ---------------------------------------------------------------------------
# Parse CISA KEV
# ---------------------------------------------------------------------------
def parse_cisa_kev(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = []

    vulns = data.get("vulnerabilities", [])
    for vuln in vulns:
        try:
            results.append(
                {
                    "source": "cisa_kev",
                    "title": vuln.get("cveID", "CISA KEV Entry"),
                    "date": vuln.get("dateAdded"),
                    "summary": vuln.get("shortDescription", ""),
                    "link": vuln.get("requiredAction", ""),
                    "actors": [],
                    "cves": [vuln.get("cveID")],  # already correct
                }
            )
        except Exception as exc:
            logger.warning("Failed to parse CISA KEV entry", extra={"error": str(exc), "raw": vuln})

    return results


# ---------------------------------------------------------------------------
# Unified CISA Campaign Fetch
# ---------------------------------------------------------------------------
async def fetch_cisa_campaigns() -> List[Dict[str, Any]]:
    results = []

    alerts_data = await _fetch_json(CISA_ALERTS_URL)
    results.extend(parse_cisa_alerts(alerts_data))

    kev_data = await _fetch_json(CISA_KEV_URL)
    results.extend(parse_cisa_kev(kev_data))

    return results
