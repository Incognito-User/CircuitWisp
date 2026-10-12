# app/trending.py

import json
from datetime import datetime
from pathlib import Path

from app.service import build_snapshot
from app.sources.kev import fetch_kev
from app.sources.exploitdb import fetch_exploitdb_recent
from app.sources.metasploit import fetch_metasploit_recent
from app.sources.nvd import fetch_recent_cves
from app.utils.logging import log_source_error

SNAPSHOT_PATH = Path("data/trending_snapshot.json")


async def compute_trending():
    """
    Dynamic trending module.
    Computes real deltas using yesterday's snapshot.
    Auto-discovers CVEs from KEV, ExploitDB, Metasploit, and NVD.
    """

    # --- 1. Discover CVEs dynamically ---
    kev = await fetch_kev()
    exploitdb = await fetch_exploitdb_recent()
    metasploit = await fetch_metasploit_recent()
    nvd = await fetch_recent_cves()

    discovered_cves = set()

    discovered_cves.update([i["cve_id"] for i in kev])
    discovered_cves.update([i["cve_id"] for i in exploitdb])
    discovered_cves.update([i["cve_id"] for i in metasploit])
    discovered_cves.update([i["cve_id"] for i in nvd])

    # Optional: include your static WATCHLIST
    discovered_cves.update(WATCHLIST)

    # --- 2. Load yesterday's snapshot ---
    if SNAPSHOT_PATH.exists():
        yesterday = json.loads(SNAPSHOT_PATH.read_text())
    else:
        yesterday = {}

    today = {}
    results = []

    # --- 3. Build today's snapshots ---
    for cve_id in discovered_cves:
        try:
            snapshot = await build_snapshot(cve_id)
        except Exception as exc:
            log_source_error("trending", cve_id, exc)
            continue

        today[cve_id] = snapshot

        # Extract today's values
        epss_today = snapshot.get("epss", {}).get("percentile", 0)
        exploits_today = len(snapshot.get("exploits", []))
        kev_today = snapshot.get("kev") is not None
        heat_today = snapshot.get("heat", 0)

        # Extract yesterday's values
        y_snap = yesterday.get(cve_id, {})
        epss_y = y_snap.get("epss", {}).get("percentile", 0)
        exploits_y = len(y_snap.get("exploits", []))
        kev_y = y_snap.get("kev") is not None
        heat_y = y_snap.get("heat", 0)

        # Compute deltas
        epss_delta = epss_today - epss_y
        exploit_delta = exploits_today - exploits_y
        kev_change = kev_today != kev_y
        heat_delta = heat_today - heat_y

        # Trending score
        trending_score = (
            (epss_delta * 0.5) +
            (exploit_delta * 0.3) +
            (1 if kev_change else 0) * 0.2 +
            (heat_delta * 0.4)
        )

        results.append({
            "cve_id": cve_id,
            "heat": heat_today,
            "epss_delta": epss_delta,
            "exploit_delta": exploit_delta,
            "kev_change": kev_change,
            "heat_delta": heat_delta,
            "trending_score": trending_score,
            "reason": build_reason(epss_delta, exploit_delta, kev_change, heat_delta)
        })

    # --- 4. Save today's snapshot for tomorrow ---
    SNAPSHOT_PATH.write_text(json.dumps(today, indent=2))

    # --- 5. Sort by trending score ---
    results.sort(key=lambda x: x["trending_score"], reverse=True)

    return {
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
        "top_trending": results
    }


def build_reason(epss_delta, exploit_delta, kev_change, heat_delta):
    reasons = []
    if epss_delta > 0.1:
        reasons.append("EPSS spike")
    if exploit_delta > 0:
        reasons.append("new exploit")
    if kev_change:
        reasons.append("KEV change")
    if heat_delta > 0:
        reasons.append("heat increase")
    if not reasons:
        reasons.append("stable")
    return reasons
