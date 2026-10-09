import httpx
import logging
from datetime import datetime
from typing import List

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/code"


def _safe_parse_timestamp(ts: str | None) -> datetime:
    if not ts:
        return datetime.utcnow()
    try:
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.utcnow()


def _safe_reliability(title: str, url: str) -> float:
    t = title.lower()
    u = url.lower()

    if any(kw in t for kw in ["poc", "exploit", "proof of concept", "weaponized"]):
        return 0.9
    if any(kw in u for kw in ["poc", "exploit"]):
        return 0.85
    return 0.7


async def fetch_github(cve_id: str) -> List[ExploitRecord]:
    headers = {}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        try:
            resp = await client.get(
                GITHUB_SEARCH_URL,
                params={"q": f"{cve_id} in:file"},
                headers=headers,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("GitHub request failed", exc=str(exc), cve=cve_id)
            return []
        except Exception as exc:
            logger.error("GitHub unexpected error", exc=str(exc), cve=cve_id)
            return []

        try:
            data = resp.json()
        except Exception:
            logger.error("GitHub returned non-JSON response", cve=cve_id)
            return []

        items = data.get("items", [])
        results: List[ExploitRecord] = []

        for item in items:
            try:
                file_url = item.get("html_url", "")
                file_name = item.get("name", "GitHub file")

                if not file_url:
                    continue

                reliability = _safe_reliability(file_name, file_url)

                record = ExploitRecord(
                    source="github",
                    cve_id=cve_id,
                    title=file_name,
                    url=file_url,
                    published=_safe_parse_timestamp(item.get("git_url")),
                    reliability=reliability,
                )

                results.append(record)

            except Exception as exc:
                logger.warning(
                    "Failed to parse GitHub entry",
                    error=str(exc),
                    raw=item,
                )

        logger.info("GitHub results fetched", count=len(results), cve=cve_id)
        return results
