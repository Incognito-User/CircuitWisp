# app/campaigns.py
# ---------------------------------------------------------------------------
# CAMPAIGN ENGINE — Unified campaign intelligence
# Aggregates CISA campaign-like alerts and MITRE intrusion sets.
# ---------------------------------------------------------------------------

from typing import List, Dict, Any

from app.sources.cisa_campaigns import fetch_cisa_campaigns
from app.sources.mitre import fetch_mitre_intrusion_sets
from app.utils.logging import log_source_error


# ---------------------------------------------------------------------------
# Unified Campaign Feed
# ---------------------------------------------------------------------------
async def get_all_campaigns() -> List[Dict[str, Any]]:
    """
    Return unified campaign intelligence from CISA + MITRE.
    Safe fallback: returns partial results if sources fail.
    """

    campaigns = []

    # -----------------------------------------------------------------------
    # CISA Campaign-like Alerts + KEV
    # -----------------------------------------------------------------------
    try:
        cisa = await fetch_cisa_campaigns()
        for entry in cisa:
            campaigns.append({
                "source": entry.get("source"),
                "title": entry.get("title"),
                "date": entry.get("date"),
                "summary": entry.get("summary"),
                "link": entry.get("link"),
                "actors": entry.get("actors", []),
                "cves": entry.get("cves", []),
            })
    except Exception as exc:
        log_source_error("campaigns", "cisa", exc)

    # -----------------------------------------------------------------------
    # MITRE Intrusion Sets (Groups)
    # -----------------------------------------------------------------------
    try:
        mitre = await fetch_mitre_intrusion_sets()
        for group in mitre:
            campaigns.append({
                "source": "mitre",
                "title": group.get("name"),
                "aliases": group.get("aliases", []),
                "description": group.get("description", ""),
                "external_references": group.get("external_references", []),
            })
    except Exception as exc:
        log_source_error("campaigns", "mitre", exc)

    return campaigns
