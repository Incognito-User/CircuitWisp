import httpx
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from app.models import ExploitRecord
from app.config import settings

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/code"

# ---------------------------------------------------------------------------
# TOKEN ROTATION (simple round-robin)
# ---------------------------------------------------------------------------

GITHUB_TOKENS: List[str] = []
if settings.github_token:
    GITHUB_TOKENS.append(settings.github_token)

_token_index = 0


def get_auth_headers() -> Dict[str, str]:
    global _token_index
    if not GITHUB_TOKENS:
        return {}
    token = GITHUB_TOKENS[_token_index % len(GITHUB_TOKENS)]
    _token_index += 1
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# SIMPLE IN-MEMORY CACHE
# ---------------------------------------------------------------------------

CACHE_TTL = timedelta(minutes=10)
_cache: Dict[str, Dict] = {}


def _get_cache(key: str):
    entry = _cache.get(key)
    if not entry:
        return None
    if entry["expires_at"] < datetime.now(timezone.utc):
        _cache.pop(key, None)
        return None
    return entry["value"]


def _set_cache(key: str, value):
    _cache[key] = {
        "value": value,
        "expires_at": datetime.now(timezone.utc) + CACHE_TTL,
    }


# ---------------------------------------------------------------------------
# FUTURE-PROOF EXPLOIT NAME MAP (seeded, then auto-extended)
# ---------------------------------------------------------------------------

MSF_NAME_MAP: Dict[str, List[str]] = {
    "CVE-2017-0144": ["ms17_010", "eternalblue"],
    "CVE-2020-1472": ["zerologon"],
    "CVE-2019-0708": ["bluekeep", "rdp_bluekeep"],
    "CVE-2022-30190": ["follina"],
    "CVE-2018-8174": ["vbscript_dll"],
}


def _safe_parse_timestamp(ts: str | None) -> datetime:
    default_dt = datetime.now(timezone.utc)
    if not ts:
        return default_dt
    try:
        ts = ts.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(ts)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return default_dt


def _safe_reliability(value) -> float:
    try:
        val = float(value)
    except Exception:
        val = 0.95
    return max(0.0, min(1.0, val))


def _score_exploit(file_name: str, file_path: str) -> float:
    """
    Very simple scoring:
    - exploit modules > auxiliary > docs/specs
    - smb/rdp/follina/etc get a small boost
    """
    score = 0.7

    path = file_path.lower()
    name = file_name.lower()

    if "modules/exploits" in path:
        score += 0.2
    elif "modules/auxiliary" in path:
        score += 0.1

    for keyword in ["smb", "rdp", "follina", "zerologon", "eternalblue", "bluekeep"]:
        if keyword in name or keyword in path:
            score += 0.05

    return max(0.0, min(1.0, score))


def _auto_learn_names(cve_id: str, items: List[Dict]):
    """
    Auto-extend MSF_NAME_MAP based on module paths and names.
    """
    names = MSF_NAME_MAP.setdefault(cve_id, [])
    for item in items:
        path = (item.get("path") or "").lower()
        name = (item.get("name") or "").lower()

        if "modules/exploits" in path or "modules/auxiliary" in path:
            base = name.replace(".rb", "")
            if base not in names:
                names.append(base)


async def _github_search(client: httpx.AsyncClient, query: str) -> Dict:
    cache_key = f"github:{query}"
    cached = _get_cache(cache_key)
    if cached is not None:
        return cached

    headers = get_auth_headers()
    resp = await client.get(
        GITHUB_SEARCH_URL,
        params={"q": f"{query} repo:rapid7/metasploit-framework"},
        headers=headers,
    )
    resp.raise_for_status()
    data = resp.json()
    _set_cache(cache_key, data)
    return data


async def fetch_metasploit(cve_id: str) -> List[ExploitRecord]:
    """
    Advanced Metasploit ingestion:
    - CVE search + exploit-name search
    - auto-learning module names
    - caching
    - token rotation
    - scoring
    """
    queries: List[str] = [cve_id]

    if cve_id in MSF_NAME_MAP:
        queries.extend(MSF_NAME_MAP[cve_id])

    results: List[ExploitRecord] = []
    seen_urls = set()

    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        for q in queries:
            try:
                data = await _github_search(client, q)
            except httpx.HTTPError as exc:
                logger.error("Metasploit request failed", exc=str(exc), query=q)
                continue
            except Exception as exc:
                logger.error("Metasploit unexpected error", exc=str(exc), query=q)
                continue

            items = data.get("items", [])
            if q == cve_id:
                _auto_learn_names(cve_id, items)

            for item in items:
                try:
                    file_url = item.get("html_url", "")
                    file_name = item.get("name", "Metasploit file")
                    file_path = item.get("path", "")

                    if not file_url or file_url in seen_urls:
                        continue
                    seen_urls.add(file_url)

                    score = _score_exploit(file_name, file_path)

                    record = ExploitRecord(
                        source="metasploit",
                        cve_id=cve_id,
                        title=file_name,
                        url=file_url,
                        published=_safe_parse_timestamp(item.get("git_url")),
                        reliability=_safe_reliability(score),
                    )

                    results.append(record)

                except Exception as exc:
                    logger.warning(
                        "Failed to parse Metasploit entry",
                        error=str(exc),
                        raw=item,
                    )

    logger.info("Metasploit results fetched", count=len(results), cve=cve_id)
    return results
