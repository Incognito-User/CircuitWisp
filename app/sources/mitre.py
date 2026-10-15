# app/sources/mitre.py
# ---------------------------------------------------------------------------
# MITRE ATT&CK CTI ingestion module (fixed for 403 + redirects)
# ---------------------------------------------------------------------------

import httpx
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

MITRE_INTRUSION_SET_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/intrusion-set/intrusion-set.json"
)

MITRE_TOOL_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/tool/tool.json"
)

MITRE_ATTACK_PATTERN_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-pattern/attack-pattern.json"
)

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/118.0.0.0 Safari/537.36"
    )
}


async def _fetch_json(url: str) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
            headers=BROWSER_HEADERS,
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()

    except Exception as exc:
        logger.warning(
            "MITRE fetch failed",
            extra={"url": url, "error": str(exc)}
        )
        return {}


# ---------------------------------------------------------------------------
# Parse intrusion sets (groups)
# ---------------------------------------------------------------------------
def parse_intrusion_sets(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = []
    objects = data.get("objects", [])

    for obj in objects:
        if obj.get("type") != "intrusion-set":
            continue

        try:
            associated_cves = []
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "cve" and ref.get("external_id"):
                    associated_cves.append(ref["external_id"])

            results.append(
                {
                    "id": obj.get("id"),
                    "name": obj.get("name"),
                    "description": obj.get("description", ""),
                    "aliases": obj.get("aliases", []),
                    "external_references": obj.get("external_references", []),
                    "associated_cves": associated_cves,
                }
            )

        except Exception as exc:
            logger.warning(
                "Failed to parse intrusion-set",
                extra={"error": str(exc), "raw": obj},
            )

    return results


# ---------------------------------------------------------------------------
# Parse tools
# ---------------------------------------------------------------------------
def parse_tools(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = []
    objects = data.get("objects", [])

    for obj in objects:
        if obj.get("type") != "tool":
            continue

        try:
            results.append(
                {
                    "id": obj.get("id"),
                    "name": obj.get("name"),
                    "description": obj.get("description", ""),
                    "tool_types": obj.get("tool_types", []),
                    "external_references": obj.get("external_references", []),
                }
            )
        except Exception as exc:
            logger.warning(
                "Failed to parse tool",
                extra={"error": str(exc), "raw": obj},
            )

    return results


# ---------------------------------------------------------------------------
# Parse attack patterns
# ---------------------------------------------------------------------------
def parse_attack_patterns(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = []
    objects = data.get("objects", [])

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        try:
            results.append(
                {
                    "id": obj.get("id"),
                    "name": obj.get("name"),
                    "description": obj.get("description", ""),
                    "kill_chain_phases": obj.get("kill_chain_phases", []),
                    "external_references": obj.get("external_references", []),
                }
            )
        except Exception as exc:
            logger.warning(
                "Failed to parse attack-pattern",
                extra={"error": str(exc), "raw": obj},
            )

    return results


# ---------------------------------------------------------------------------
# Public fetch functions
# ---------------------------------------------------------------------------
async def fetch_mitre_intrusion_sets() -> List[Dict[str, Any]]:
    data = await _fetch_json(MITRE_INTRUSION_SET_URL)
    return parse_intrusion_sets(data)


async def fetch_mitre_tools() -> List[Dict[str, Any]]:
    data = await _fetch_json(MITRE_TOOL_URL)
    return parse_tools(data)


async def fetch_mitre_attack_patterns() -> List[Dict[str, Any]]:
    data = await _fetch_json(MITRE_ATTACK_PATTERN_URL)
    return parse_attack_patterns(data)


async def fetch_mitre_cti() -> Dict[str, List[Dict[str, Any]]]:
    intrusion_sets = await fetch_mitre_intrusion_sets()
    tools = await fetch_mitre_tools()
    attack_patterns = await fetch_mitre_attack_patterns()

    return {
        "intrusion_sets": intrusion_sets,
        "tools": tools,
        "attack_patterns": attack_patterns,
    }
