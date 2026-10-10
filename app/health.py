# app/health.py

from datetime import datetime
from app.config import (
    SHODAN_API_KEY,
    GREYNOISE_API_KEY,
    GITHUB_TOKEN,
)
from app.utils.logging import log_source_error

import httpx


async def check_http(url: str, source: str) -> bool:
    """
    Minimal, OWASP‑aligned HTTP health check.
    - No sensitive data in logs
    - No exception leakage
    - Timeouts enforced
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            return resp.status_code < 500
    except Exception as exc:
        log_source_error(source, "health-check", exc)
        return False


async def health_sources():
    """
    Returns real-time health status for all intel sources.
    OWASP-compliant:
    - No secrets returned
    - No stack traces
    - No internal error messages
    - Only boolean health indicators
    """

    results = {
        "timestamp": datetime.utcnow().isoformat() + "Z",

        # Public sources
        "epss": await check_http("https://api.first.org/data/v1/epss", "epss"),
        "kev": await check_http("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "kev"),
        "nvd": await check_http("https://services.nvd.nist.gov/rest/json/cves/2.0", "nvd"),
        "exploitdb": await check_http("https://www.exploit-db.com", "exploitdb"),
        "metasploit": await check_http("https://raw.githubusercontent.com/rapid7/metasploit-framework/master/README.md", "metasploit"),
        "vendor_rss": await check_http("https://www.debian.org/security/dsa", "vendor-rss"),

        # Authenticated sources
        "github": bool(GITHUB_TOKEN),
        "shodan": bool(SHODAN_API_KEY),
        "greynoise": bool(GREYNOISE_API_KEY),
    }

    return results
