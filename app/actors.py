# app/actors.py
# ---------------------------------------------------------------------------
# ACTOR ENGINE — Threat actor enrichment and CVE association
# Provides MITRE group mapping, campaign links, tooling usage, and actor heat.
# ---------------------------------------------------------------------------

from app.sources.mitre import fetch_mitre_intrusion_sets
from app.sources.cisa_campaigns import fetch_cisa_campaigns
from app.sources.exploitdb import fetch_exploitdb
from app.sources.metasploit import fetch_metasploit
from app.sources.github import fetch_github
from app.utils.logging import log_source_error


# ---------------------------------------------------------------------------
# Actor Mapping for a CVE
# ---------------------------------------------------------------------------
async def get_actor_mapping(cve_id: str):
    """
    Return actor intelligence associated with a CVE.
    Includes MITRE groups, campaigns, tooling, and actor heat.
    """

    actors = []
    campaigns = []
    tools = []

    # -----------------------------------------------------------------------
    # MITRE Groups (intrusion sets)
    # -----------------------------------------------------------------------
    try:
        mitre = await fetch_mitre_intrusion_sets()
        actors = [
            g for g in mitre
            if any(
                ref.get("external_id") == cve_id
                for ref in g.get("external_references", [])
            )
        ]
    except Exception as exc:
        log_source_error("actors", "mitre", exc)

    # -----------------------------------------------------------------------
    # CISA Campaigns
    # -----------------------------------------------------------------------
    try:
        cisa = await fetch_cisa_campaigns()
        campaigns = [c for c in cisa if cve_id in c.get("cves", [])]
    except Exception as exc:
        log_source_error("actors", "cisa", exc)

    # -----------------------------------------------------------------------
    # Tooling-based CVE associations
    # -----------------------------------------------------------------------
    try:
        edb = await fetch_exploitdb(cve_id)
        ms = await fetch_metasploit(cve_id)
        gh = await fetch_github(cve_id)
        tools = edb + ms + gh
    except Exception as exc:
        log_source_error("actors", "tools", exc)

    # -----------------------------------------------------------------------
    # Actor heat score (simple heuristic)
    # -----------------------------------------------------------------------
    heat = len(actors) * 0.5 + len(campaigns) * 0.3 + len(tools) * 0.2

    return {
        "cve_id": cve_id,
        "actors": actors,
        "campaigns": campaigns,
        "tools": [t.to_dict() for t in tools],
        "heat": heat,
    }


# ---------------------------------------------------------------------------
# Actor Detail Lookup
# ---------------------------------------------------------------------------
async def get_actor_by_name(actor_name: str):
    """
    Return enriched intelligence for a specific threat actor.
    Includes aliases, tooling, techniques, campaigns, and related CVEs.
    """

    try:
        mitre = await fetch_mitre_intrusion_sets()
        actor = next((g for g in mitre if actor_name.lower() in g["name"].lower()), None)
        return actor or {"error": "actor not found"}
    except Exception as exc:
        log_source_error("actors", actor_name, exc)
        return {"error": "lookup failed"}
