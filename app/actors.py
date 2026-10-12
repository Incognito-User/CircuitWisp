# app/actors.py

from app.sources.mitre import fetch_mitre_groups
from app.sources.cisa import fetch_cisa_advisories
from app.sources.exploitdb import search_exploitdb
from app.sources.metasploit import search_metasploit
from app.sources.github import search_github_pocs
from app.service import build_snapshot
from app.utils.logging import log_source_error


async def get_actor_mapping(cve_id: str):
    """
    Dynamic actor enrichment for a given CVE.
    Pulls MITRE ATT&CK groups, CISA advisories, and tooling-based CVE associations.
    """

    enriched_actors = []

    # --- 1. Fetch MITRE ATT&CK groups ---
    try:
        mitre_groups = await fetch_mitre_groups()
    except Exception as exc:
        log_source_error("actors", "mitre", exc)
        mitre_groups = []

    # --- 2. Fetch CISA advisories ---
    try:
        cisa_advisories = await fetch_cisa_advisories()
    except Exception as exc:
        log_source_error("actors", "cisa", exc)
        cisa_advisories = []

    # --- 3. Identify actors linked to this CVE ---
    for group in mitre_groups:
        # Check if MITRE lists this CVE directly
        mitre_cves = group.get("associated_cves", [])
        if cve_id.upper() in mitre_cves:
            enriched_actors.append(await enrich_actor(group, cve_id, cisa_advisories))

        # Check CISA advisories for actor → CVE links
        for advisory in cisa_advisories:
            if cve_id.upper() in advisory.get("cves", []):
                if group["name"].lower() in advisory.get("actors", "").lower():
                    enriched_actors.append(await enrich_actor(group, cve_id, cisa_advisories))

    return {
        "cve_id": cve_id,
        "actors": enriched_actors,
        "count": len(enriched_actors)
    }


async def enrich_actor(group: dict, cve_id: str, cisa_advisories: list):
    """
    Build a full dynamic actor profile.
    """

    actor_name = group["name"]
    tools = group.get("tools", [])
    techniques = group.get("techniques", [])
    aliases = group.get("aliases", [])

    # --- 1. Map tools → CVEs ---
    related_cves = set()

    for tool in tools:
        try:
            related_cves.update([r["cve_id"] for r in await search_exploitdb(tool)])
            related_cves.update([r["cve_id"] for r in await search_metasploit(tool)])
            related_cves.update([r["cve_id"] for r in await search_github_pocs(tool)])
        except Exception as exc:
            log_source_error("actors", tool, exc)

    related_cves = list(related_cves)

    # --- 2. Map actor → campaigns ---
    campaigns = []
    for advisory in cisa_advisories:
        if actor_name.lower() in advisory.get("actors", "").lower():
            campaigns.append({
                "title": advisory.get("title"),
                "date": advisory.get("date"),
                "cves": advisory.get("cves", [])
            })

    # --- 3. Build CVE snapshots ---
    cve_snapshots = []
    for rcve in related_cves:
        try:
            snap = await build_snapshot(rcve)
            cve_snapshots.append(snap)
        except Exception as exc:
            log_source_error("actors", rcve, exc)

    # --- 4. Compute actor heat score ---
    actor_heat = sum(s.get("heat", 0) for s in cve_snapshots)

    # --- 5. Return enriched actor profile ---
    return {
        "actor": actor_name,
        "aliases": aliases,
        "tools": tools,
        "techniques": techniques,
        "campaigns": campaigns,
        "related_cves": related_cves,
        "cve_snapshots": cve_snapshots,
        "actor_heat": actor_heat,
        "notes": f"Dynamically enriched actor profile for {actor_name}"
    }
