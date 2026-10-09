import httpx
import logging
from datetime import datetime

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/code"

# ---------------------------------------------------------------------------
# FUTURE-PROOF EXPLOIT NAME MAP
# ---------------------------------------------------------------------------
# This map lets you correlate CVE IDs to Metasploit module names.
# You can expand this over time, or auto-learn new names from GitHub results.
MSF_NAME_MAP = {
    "CVE-2017-0144": ["ms17_010", "eternalblue", "smb_ms17_010"],
    "CVE-2020-1472": ["zerologon"],
    "CVE-2019-0708": ["bluekeep", "rdp_bluekeep"],
    "CVE-2022-30190": ["follina"],
    "CVE-2018-8174": ["vbscript_dll"],
}

# ---------------------------------------------------------------------------
# SAFE HELPERS
# ---------------------------------------------------------------------------

def _safe_parse_timestamp(ts: str | None) -> datetime:
    if not ts:
        return datetime.utcnow()
    try:
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.utcnow()


def _safe_reliability(value) -> float:
    try:
        val = float(value)
    except Exception:
        val = 0.95
    return max(0.0, min(1.0, val))


# ---------------------------------------------------------------------------
# MAIN INGESTION LOGIC
# ---------------------------------------------------------------------------

async def fetch_metasploit(cve_id: str) -> list[ExploitRecord]:
    """
    Future-proof Metasploit ingestion:
    - Dual-phase search (CVE + exploit names)
    - Safe JSON parsing
    - Safe field extraction
    - Safe timestamp handling
    - Safe reliability clamping
    - Deduplication
    """

    queries = [cve_id]

    # Add exploit-name heuristics
    if cve_id in MSF_NAME_MAP:
        queries.extend(MSF_NAME_MAP[cve_id])

    results: list[ExploitRecord] = []
    seen_urls = set()

    headers = {}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        for q in queries:
            try:
                resp = await client.get(
                    GITHUB_SEARCH_URL,
                    params={"q": f"{q} repo:rapid7/metasploit-framework"},
                    headers=headers,
                )
                resp.raise_for_status()

                try:
                    data = resp.json()
                except Exception:
                    logger.error("Metasploit API returned non-JSON response", q=q)
                    continue

                items = data.get("items", [])
                for item in items:
                    try:
                        file_url = item.get("html_url", "")
                        file_name = item.get("name", "Metasploit module")

                        # Deduplicate
                        if file_url in seen_urls:
                            continue
                        seen_urls.add(file_url)

                        record = ExploitRecord(
                            source="metasploit",
                            cve_id=cve_id,
                            title=file_name,
                            url=file_url,
                            published=_safe_parse_timestamp(item.get("git_url")),
                            reliability=_safe_reliability(0.95),
                        )

                        results.append(record)

                    except Exception as exc:
                        logger.warning(
                            "Failed to parse Metasploit module entry",
                            error=str(exc),
                            raw=item,
                        )

            except httpx.HTTPError as exc:
                logger.error("Metasploit request failed", exc=str(exc), q=q)
                continue

    logger.info("Metasploit results fetched", count=len(results), cve=cve_id)
    return results
