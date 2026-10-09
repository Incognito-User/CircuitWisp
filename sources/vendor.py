import httpx
import logging
from datetime import datetime, timezone
from typing import List

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

MSRC_API = "https://api.msrc.microsoft.com/cvrf/v2.0/cve/"
CISCO_SEARCH = "https://sec.cloudapps.cisco.com/security/center/search.x"


def _safe_parse_timestamp(ts: str | None) -> datetime:
    if not ts:
        return datetime.now(timezone.utc)
    try:
        ts = ts.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(ts)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _safe_reliability_vendor(vendor: str) -> float:
    v = vendor.lower()
    if v in {"msrc", "microsoft"}:
        return 0.95
    if v in {"cisco", "oracle", "vmware", "redhat"}:
        return 0.9
    return 0.8


async def _fetch_msrc(client: httpx.AsyncClient, cve_id: str) -> List[ExploitRecord]:
    headers = {"Accept": "application/json"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"

    url = MSRC_API + cve_id

    try:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
    except Exception as exc:
        # FIXED LOGGING
        logger.warning(f"MSRC advisory fetch failed for {url}: {exc}")
        return []

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning(f"MSRC returned non-JSON for {url}: {exc}")
        return []

    title = data.get("DocumentTitle", f"MSRC advisory for {cve_id}")
    published = data.get("DocumentTracking", {}).get("InitialReleaseDate")

    record = ExploitRecord(
        source="msrc",
        cve_id=cve_id,
        title=title,
        url=url,
        published=_safe_parse_timestamp(published),
        reliability=_safe_reliability_vendor("msrc"),
    )

    return [record]


async def _fetch_cisco(client: httpx.AsyncClient, cve_id: str) -> List[ExploitRecord]:
    params = {"keyword": cve_id}
    url = CISCO_SEARCH

    try:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
    except Exception as exc:
        # FIXED LOGGING
        logger.warning(f"Cisco advisory fetch failed for {url}: {exc}")
        return []

    # Cisco returns HTML; presence = confirmation
    record = ExploitRecord(
        source="cisco",
        cve_id=cve_id,
        title=f"Cisco advisory search for {cve_id}",
        url=f"{url}?keyword={cve_id}",
        published=datetime.now(timezone.utc),
        reliability=_safe_reliability_vendor("cisco"),
    )

    return [record]


async def fetch_vendor_advisories(cve_id: str) -> List[ExploitRecord]:
    results: List[ExploitRecord] = []

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        msrc = await _fetch_msrc(client, cve_id)
        cisco = await _fetch_cisco(client, cve_id)

        results.extend(msrc)
        results.extend(cisco)

    logger.info(f"Vendor advisories fetched for {cve_id}: {len(results)} records")
    return results
