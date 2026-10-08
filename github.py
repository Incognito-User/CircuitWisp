import httpx
import logging
from datetime import datetime

from app.config import settings
from app.models import ExploitRecord

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"


async def fetch_github(cve_id: str) -> list[ExploitRecord]:
    """
    Search GitHub repositories for mentions of the CVE.
    Normalizes results into ExploitRecord objects.
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

    # Add token if provided
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"

    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
            response = await client.get(GITHUB_SEARCH_URL, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

    except httpx.HTTPError as exc:
        logger.error("GitHub API request failed", exc=str(exc), cve=cve_id)
        return []

    items = data.get("items", [])
    results: list[ExploitRecord] = []

    for repo in items:
        try:
            updated_at = repo.get("updated_at", "")
            published = (
                datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                if updated_at
                else datetime.utcnow()
            )

            record = ExploitRecord(
                source="github",
                cve_id=cve_id,
                title=repo.get("full_name", "Unknown Repository"),
                url=repo.get("html_url", ""),
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


def _estimate_repo_reliability(repo: dict) -> float:
    """
    Simple reliability scoring heuristic for GitHub PoCs.
    This will evolve later as CircuitWisp's scoring engine matures.
    """
    stars = repo.get("stargazers_count", 0)
    forks = repo.get("forks_count", 0)
    watchers = repo.get("watchers_count", 0)

    # Basic heuristic:
    # - More stars/forks/watchers = more reliable PoC
    # - Cap at 1.0
    score = min(1.0, (stars * 0.01) + (forks * 0.02) + (watchers * 0.005))

    return round(score, 2)
