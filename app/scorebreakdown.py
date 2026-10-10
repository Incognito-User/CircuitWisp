# app/scorebreakdown.py

from app.scoring import calculate_heat_score
from app.service import build_snapshot
from app.utils.logging import log_source_error


async def score_breakdown(cve_id: str):
    """
    Returns a safe, OWASP-aligned breakdown of how the heat score was calculated.
    No secrets, no stack traces, no internal exceptions.
    """

    try:
        snapshot = await build_snapshot(cve_id)
    except Exception as exc:
        log_source_error("scorebreakdown", cve_id, exc)
        return {
            "cve_id": cve_id,
            "error": "Unable to compute score breakdown at this time."
        }

    # Extract relevant fields
    epss = snapshot.get("epss", {})
    kev = snapshot.get("kev")
    exploits = snapshot.get("exploits", [])
    nvd = snapshot.get("nvd", {})
    heat = snapshot.get("heat")
    risk = snapshot.get("risk_level")

    # Build safe breakdown
    breakdown = {
        "cve_id": cve_id,
        "heat_score": heat,
        "risk_level": risk,
        "components": {
            "epss": {
                "score": epss.get("epss"),
                "percentile": epss.get("percentile"),
                "weight": 0.5
            },
            "kev": {
                "is_known_exploited": kev is not None,
                "weight": 0.2
            },
            "exploits": {
                "count": len(exploits),
                "weight": 0.2
            },
            "nvd": {
                "has_cvss": bool(nvd),
                "weight": 0.1
            }
        }
    }

    return breakdown
