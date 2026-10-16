# app/tools.py
# ---------------------------------------------------------------------------
# TOOL INTELLIGENCE ENGINE — Enriched tooling-based CVE analysis
# Provides CVE associations, exploit metadata, actor usage, campaigns, snapshots.
# ---------------------------------------------------------------------------

from typing import Dict, Any, List

from app.sources.exploitdb import fetch_exploitdb
from app.sources.metasploit import fetch_metasploit
from app.sources.github import fetch_github
from app.actors import get_actor_mapping
from app.campaigns import get_all_campaigns
from app.service import build_snapshot
from app.utils.logging import log_source_error


# ---------------------------------------------------------------------------
# Tool Intelligence Lookup
# ---------------------------------------------------------------------------
async def get_tool_intel(tool_name: str) -> Dict[str, Any]:
    """
    Return enriched intelligence for a specific tool.
    Includes related CVEs, exploit metadata, actor usage, campaigns, snapshots.
    """

    related_cves: List[str] = []
    exploit_records = []

    # -----------------------------------------------------------------------
    # ExploitDB
    # -----------------------------------------------------------------------
    try:
        edb = await fetch_exploitdb(tool_name)
        exploit_records.extend(edb)
        related_cves.extend([r.cve_id for r in edb if r.cve_id])
    except Exception as exc:
        log_source_error("tools", "exploitdb", exc)

    # -----------------------------------------------------------------------
    # Metasploit
    # -----------------------------------------------------------------------
    try:
        ms = await fetch_metasploit(tool_name)
        exploit_records.extend(ms)
        related_cves.extend([r.cve_id for r in ms if r.cve_id])
    except Exception as exc:
        log_source_error("tools", "metasploit", exc)

    # -----------------------------------------------------------------------
    # GitHub PoCs
    # -----------------------------------------------------------------------
    try:
        gh = await fetch_github(tool_name)
        exploit_records.extend(gh)
        related_cves.extend([r.cve_id for r in gh if r.cve_id])
    except Exception as exc:
        log_source_error("tools", "github", exc)

    related_cves = list(set(related_cves))

    # -----------------------------------------------------------------------
    # Build snapshots for each CVE
    # -----------------------------------------------------------------------
    snapshots = []
    for cve in related_cves:
        try:
            snapshots.append(await build_snapshot(cve))
        except Exception as exc:
            log_source_error("tools", cve, exc)

    # -----------------------------------------------------------------------
    # Actor usage
    # -----------------------------------------------------------------------
    actors = []
    for cve in related_cves:
        try:
            actors.append(await get_actor_mapping(cve))
        except Exception as exc:
            log_source_error("tools", f"actor-{cve}", exc)

    # -----------------------------------------------------------------------
    # Campaigns
    # -----------------------------------------------------------------------
    try:
        campaigns = await get_all_campaigns()
    except Exception as exc:
        log_source_error("tools", "campaigns", exc)
        campaigns = []

    return {
        "tool": tool_name,
        "related_cves": related_cves,
        "exploit_records": [r.to_dict() for r in exploit_records],
        "snapshots": snapshots,
        "actors": actors,
        "campaigns": campaigns,
    }
