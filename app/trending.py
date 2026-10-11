# app/trending.py

from datetime import datetime
from app.service import build_snapshot
from app.utils.logging import log_source_error

# CVEs you want to monitor daily (expand later or auto-populate)
WATCHLIST = [
    "CVE-2021-44228",
    "CVE-2020-1472",
    "CVE-2019-0708",
    "CVE-2017-0144",
    "CVE-2023-34362"
]


async def compute_trending():
    """
    Stateless trending module.
    Computes 'movement' based on current snapshot values.
    Later, you can add persistence for true deltas.
    """

    results = []

    for cve_id in WATCHLIST:
        try:
            snapshot = await build_snapshot(cve_id)
        except Exception as exc:
            log_source_error("trending", cve_id, exc)
            continue

        # Extract components
        epss = snapshot.get("epss", {})
        exploits = snapshot.get("exploits", [])
        kev = snapshot.get("kev")
        heat = snapshot.get("heat", 0)

        # Heuristic deltas (stateless version)
        epss_delta = epss.get("percentile", 0)
        exploit_delta = len(exploits)
        kev_change = kev is not None

        # Simple trending score
        trending_score = (
            (epss_delta * 0.5) +
            (exploit_delta * 0.3) +
            (1 if kev_change else 0) * 0.2
        )

        results.append({
            "cve_id": cve_id,
            "heat": heat,
            "epss_delta": epss_delta,
            "exploit_delta": exploit_delta,
            "kev_change": kev_change,
            "trending_score": trending_score,
            "reason": build_reason(epss_delta, exploit_delta, kev_change)
        })

    # Sort by trending score
    results.sort(key=lambda x: x["trending_score"], reverse=True)

    return {
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
        "top_trending": results
    }


def build_reason(epss_delta, exploit_delta, kev_change):
    reasons = []
    if epss_delta > 0.5:
        reasons.append("EPSS spike")
    if exploit_delta > 0:
        reasons.append("new exploit")
    if kev_change:
        reasons.append("KEV activity")
    if not reasons:
        reasons.append("stable")
    return reasons
