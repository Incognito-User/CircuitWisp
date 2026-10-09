import httpx
import logging
from datetime import datetime

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

GITHUB_CODE_SEARCH_URL = "https://api.github.com/search/code"


async def fetch_metasploit(cve_id: str) -> list[ExploitRecord]:
    """
    Hardened Metasploit ingestion using GitHub code search:
    - Safe JSON parsing
    - Safe field extraction
    - Safe timestamp fallback
    - Safe reliability heuristic
    """

    # Build correct GitHub search query
    params = {
        "q": f"{cve_id} repo:rapid7/metasploit-framework",
        "per_page": 20,
    }

    headers = {"Accept": "application/vnd.github+json"}

    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"

    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
            resp = await client.get(GITHUB_CODE_SEARCH_URL, params=params, headers=headers)
            resp.raise_for_status()

            try:
                data = resp.json()
            except Exception:
                logger.error("Metasploit search returned non-JSON response", cve=cve_id)
                return []

    except httpx.HTTPError as exc:
        logger.error("Metasploit GitHub search failed", exc=str(exc), cve=cve_id)
        return []

    items = data.get("items", [])
    results: list[ExploitRecord] = []

    for item in items:
        try:
            # Extract module path and name
            module_name = item.get("name") or "Metasploit module"
            module_path = item.get("path") or ""
            html_url = item.get("html_url") or ""

            # Use repository updated_at as best available timestamp
            repo_info = item.get("repository", {})
            updated_at = repo_info.get("updated_at")
            published = _safe_parse_timestamp(updated_at)

            record = ExploitRecord(
                source="metasploit",
                cve_id=cve_id,
                title=module_name,
                url=html_url,
                published=published,
                reliability=_estimate_module_reliability(module_path),
            )

            results.append(record)

        except Exception as exc:
            logger.warning(
                "Failed to parse Metasploit module entry",
                error=str(exc),
                raw=item,
            )

    logger.info("Metasploit results fetched", count=len(results), cve=cve_id)
    return results


def _safe_parse_timestamp(ts: str | None) -> datetime:
    """
    Safely parse timestamps from GitHub repo metadata.
    Falls back to UTC now if malformed or missing.
    """
    if not ts:
        return datetime.utcnow()

    try:
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.utcnow()


def _estimate_module_reliability(path: str) -> float:
    """
    Simple reliability heuristic for Metasploit modules.
    """
    path = path.lower()

    # Exploit modules are more reliable than auxiliary modules
    if "exploits" in path:
        return 0.95
    if "auxiliary" in path:
        return 0.75
    return 0.6
