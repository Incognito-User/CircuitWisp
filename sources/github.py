import httpx
import logging
from datetime import datetime

from app.config import settings
from app.models import ExploitRecord

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"


async def fetch_github(cve_id: str) -> list[ExploitRecord]:
    """
    Hardened GitHub ingestion:
    - Safe JSON parsing
    - Safe timestamp parsing
    - Safe reliability scoring
    - Safe field extraction
    """

    params = {
        "q": f"{cve_id} exploit proof-of-concept",
        "sort": "updated",
        "order": "desc",
        "per_page": 20,
    }

    headers = {
        "Accept": "application/vnd.github+json",
    }

    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"

    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
            response = await client.get(GITHUB_SEARCH_URL, params=params, headers=headers)
            response.raise_for_status()

            try:
                data = response.json()
            except Exception:
                logger.error("GitHub returned non-JSON response", cve=cve_id)
                return []

    except httpx.HTTPError as exc:
        logger.error("GitHub API request failed", exc=str(exc), cve=cve_id)
        return []

    items = data.get("items", [])
    results: list[ExploitRecord] = []

    for repo in items:
        try:
            updated_at = repo.get("updated_at")

            # Safe timestamp parsing
            published = _safe_parse_timestamp(updated_at)

            record = ExploitRecord(
                source="github",
                cve_id=cve_id,
                title=repo.get("full_name") or "Unknown Repository",
                url=repo.get("html_url") or "",
                published=published,
                reliability=_estimate_repo_reliability(repo),
            )

            results.append(record)

        except Exception as exc:
            logger.warning(
                "Failed to parse GitHub repo entry",
                error=str(exc),
                raw=repo,
            )

    logger.info("GitHub results fetched", count=len(results), cve=cve_id)
    return results


def _safe_parse_timestamp(ts: str | None) -> datetime:
    """
    Safely parse GitHub timestamps.
    Falls back to UTC now if malformed or missing.
    """
    if not ts:
        return datetime.utcnow()

    try:
        # Normalize Z suffix
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.utcnow()


def _estimate_repo_reliability(repo: dict) -> float:
    """
    Hardened reliability scoring:
    - Safe numeric conversion
    - Clamped values
    """

    def safe_int(value):
        try:
            return int(value)
        except Exception:
            return 0

    stars = safe_int(repo.get("stargazers_count"))
    forks = safe_int(repo.get("forks_count"))
    watchers = safe_int(repo.get("watchers_count"))

    score = (stars * 0.01) + (forks * 0.02) + (watchers * 0.005)
    score = max(0.0, min(1.0, score))

    return round(score, 2)
