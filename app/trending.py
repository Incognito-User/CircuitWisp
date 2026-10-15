# app/trending.py
# ---------------------------------------------------------------------------
# TRENDING ENGINE — DAILY DELTA ANALYSIS
# Computes trending CVEs using multi-source discovery, snapshot deltas,
# and SREI priority scoring.
# ---------------------------------------------------------------------------

import json
from datetime import datetime
from pathlib import Path

from app.service import build_snapshot

# Discovery sources
from app.sources.kev import fetch_kev_recent
from app.sources.exploitdb import fetch_exploitdb_recent
from app.sources.metasploit import fetch_metasploit_recent
from app.sources.nvd import fetch_recent_cves
from app.sources.github import fetch_github_recent
from app.sources.greynoise import fetch_greynoise_recent
from app.sources.shodan import fetch_shodan_recent

from app.utils.logging import log_source_error

from app.srei import compute_srei
from app.techstack import load_tech_stack

SNAPSHOT_PATH = Path("data/trending_snapshot.json")


# ---------------------------------------------------------------------------
# Safe discovery wrapper (supports async + sync functions)
# ---------------------------------------------------------------------------
async def safe_fetch(name, func):
    try:
        result = func()
        if hasattr(result, "__await__"):  # async function
            return await result
        return result                     # sync function
    except Exception as exc:
        log_source_error("trending", name, exc)
        return []


# ---------------------------------------------------------------------------
# Compute trending CVEs using daily deltas + SREI priority
# ---------------------------------------------------------------------------
async def compute_trending():
    """Discover CVEs, compute daily deltas, enrich with SREI, and rank by priority."""

    # Load tech stack (safe fallback)
    tech_stack = load_tech_stack()

    # -----------------------------------------------------------------------
    # Multi-source CVE discovery (all safe)
    # -----------------------------------------------------------------------
    kev = await safe_fetch("kev", fetch_kev_recent)
    exploitdb = await safe_fetch("exploitdb", fetch_exploitdb_recent)
    metasploit = await safe_fetch("metasploit", fetch_metasploit_recent)
    nvd = await safe_fetch("nvd", fetch_recent_cves)
    github = await safe_fetch("github", fetch_github_recent)
    greynoise = await safe_fetch("greynoise", fetch_greynoise_recent)
    shodan = await safe_fetch("shodan", fetch_shodan_recent)

    discovered_cves = set()
    for src in (kev, exploitdb, metasploit, nvd, github, greynoise, shodan):
        discovered_cves.update([i["cve_id"] for i in src])

    # -----------------------------------------------------------------------
    # Load yesterday's snapshot
    # -----------------------------------------------------------------------
    if SNAPSHOT_PATH.exists():
        yesterday = json.loads(SNAPSHOT_PATH.read_text())
    else:
        yesterday = {}

    today = {}
    results = []

    # -----------------------------------------------------------------------
    # Build today's snapshots + compute SREI
    # -----------------------------------------------------------------------
    for cve_id in discovered_cves:
        try:
            snapshot = await build_snapshot(cve_id)
        except Exception as exc:
            log_source_error("trending", cve_id, exc)
            continue

        today[cve_id] = snapshot
        y_snap = yesterday.get(cve_id, {})

        srei = compute_srei(
            cve_id=cve_id,
            today_snapshot=snapshot,
            yesterday_snapshot=y_snap,
            tech_stack=tech_stack,
            internet_facing=False,  # exposure logic can be added later
        )

        results.append({
            "cve_id": cve_id,
            "heat": snapshot.get("heat", 0),
            "srei": srei,
        })

    # -----------------------------------------------------------------------
    # Persist today's snapshot
    # -----------------------------------------------------------------------
    SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_PATH.write_text(json.dumps(today, indent=2))

    # -----------------------------------------------------------------------
    # Sort trending results by SREI priority + heat tie-breaker
    # -----------------------------------------------------------------------
    priority_order = {"P1": 0, "P2": 1, "P3": 2}

    results.sort(
        key=lambda x: (
            priority_order.get(x["srei"]["priority"], 2),
            -x["heat"]
        )
    )

    # -----------------------------------------------------------------------
    # Return trending feed
    # -----------------------------------------------------------------------
    return {
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
        "top_trending": results,
    }
