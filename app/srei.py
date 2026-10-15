# app/srei.py
# ---------------------------------------------------------------------------
# SREI ENGINE — Stack-Relevant Exploitation Interest
# Computes exploitation interest using:
# - Stack match
# - Chatter signals
# - Feasibility (CVSSv4 → CVSSv3.1 fallback)
# - KEV presence
# - Exposure (internet-facing)
#
# OWASP-aligned transparency:
# - Deterministic scoring rules
# - Safe fallbacks for missing data
# - Clear signal definitions
# ---------------------------------------------------------------------------

from datetime import datetime, timezone
from typing import Dict, Any, List


# ---------------------------------------------------------------------------
# UTC Timestamp Helper
# ---------------------------------------------------------------------------
def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Stack Match Classification
# ---------------------------------------------------------------------------
def classify_stack_match(snapshot: Dict[str, Any], tech_stack: List[str]) -> str:
    """
    Stack Match: confirmed | probable | third_party | not_present | unknown

    Safe fallback:
    - If no tech stack configured → 'unknown'
    - If no NVD description → 'unknown'
    """

    if not tech_stack:
        return "unknown"

    desc = snapshot.get("nvd", {}).get("description", "") or ""
    desc_lower = desc.lower()

    # Direct product match → confirmed
    for product in tech_stack:
        if product.lower() in desc_lower:
            return "confirmed"

    # TODO: Add CPE vendor hierarchy for probable / third_party
    return "unknown"


# ---------------------------------------------------------------------------
# Chatter Signal Computation
# ---------------------------------------------------------------------------
def compute_chatter(today: Dict[str, Any], yesterday: Dict[str, Any]) -> Dict[str, Any]:
    """
    Chatter levels:
      - baseline (0 signals)
      - elevated (1 signal)
      - high (2+ signals)

    Signals:
      - EPSS delta >= 0.10
      - EPSS crossing 0.50
      - new exploit (GitHub/Metasploit/ExploitDB)
      - KEV change
      - GreyNoise IP increase
      - Shodan exposure increase
      - new actor link
    """

    signals = []

    # EPSS signals
    epss_today = today.get("epss", {}).get("percentile", 0) or 0
    epss_y = yesterday.get("epss", {}).get("percentile", 0) or 0

    if epss_today - epss_y >= 0.10:
        signals.append("epss_delta>=0.10")
    if epss_y < 0.50 <= epss_today:
        signals.append("epss_crossed_0.50")

    # Exploit signals
    if len(today.get("exploits", [])) > len(yesterday.get("exploits", [])):
        signals.append("new_exploit")

    # KEV signals
    if (today.get("kev") is not None) != (yesterday.get("kev") is not None):
        signals.append("kev_change")

    # GreyNoise signals
    if (today.get("greynoise", {}).get("ip_count", 0) or 0) > (
        yesterday.get("greynoise", {}).get("ip_count", 0) or 0
    ):
        signals.append("greynoise_increase")

    # Shodan signals
    if (today.get("shodan", {}).get("exposure_count", 0) or 0) > (
        yesterday.get("shodan", {}).get("exposure_count", 0) or 0
    ):
        signals.append("shodan_exposure_increase")

    # Actor signals
    if today.get("actors") and not yesterday.get("actors"):
        signals.append("new_actor_link")

    # Determine chatter level
    count = len(signals)
    if count == 0:
        level = "baseline"
    elif count == 1:
        level = "elevated"
    else:
        level = "high"

    return {
        "level": level,
        "signals": signals,
    }


# ---------------------------------------------------------------------------
# Feasibility (CVSS-based)
# ---------------------------------------------------------------------------
def feasibility_from_cvss4(cvss: Dict[str, Any]) -> str:
    """Feasibility mapping for CVSSv4."""
    if (
        cvss.get("AV") == "N"
        and cvss.get("PR") == "N"
        and cvss.get("UI") == "N"
        and cvss.get("AC") == "L"
    ):
        return "high"
    if cvss.get("AV") == "N":
        return "moderate"
    return "low"


def feasibility_from_cvss3(cvss: Dict[str, Any]) -> str:
    """Feasibility mapping for CVSSv3.1."""
    if (
        cvss.get("AV") == "N"
        and cvss.get("PR") == "N"
        and cvss.get("UI") == "N"
        and cvss.get("AC") == "L"
    ):
        return "high"
    if cvss.get("AV") == "N":
        return "moderate"
    return "low"


def compute_feasibility(snapshot: Dict[str, Any]) -> str:
    """
    Feasibility: low | moderate | high
    Safe fallback:
    - Prefer CVSSv4
    - Fall back to CVSSv3.1
    - If missing → moderate
    """

    cvss4 = snapshot.get("nvd", {}).get("cvss_v4")
    cvss3 = snapshot.get("nvd", {}).get("cvss_v3")

    if cvss4:
        return feasibility_from_cvss4(cvss4)
    if cvss3:
        return feasibility_from_cvss3(cvss3)

    return "moderate"


# ---------------------------------------------------------------------------
# Priority Computation
# ---------------------------------------------------------------------------
def compute_priority(
    stack_match: str,
    chatter_level: str,
    feasibility: str,
    internet_facing: bool,
    kev_present: bool,
) -> str:
    """
    Priority rules:
      - KEV + confirmed → P1
      - confirmed + high chatter + high feasibility + internet-facing → P1
      - probable/third_party + elevated/high chatter → P2
      - unknown/not_present → P3
    """

    if kev_present and stack_match == "confirmed":
        return "P1"

    if (
        stack_match == "confirmed"
        and chatter_level == "high"
        and feasibility == "high"
        and internet_facing
    ):
        return "P1"

    if stack_match in ("confirmed", "probable", "third_party"):
        if chatter_level in ("elevated", "high") and feasibility in ("moderate", "high"):
            return "P2"

    return "P3"


# ---------------------------------------------------------------------------
# Top-Level SREI Computation
# ---------------------------------------------------------------------------
def compute_srei(
    cve_id: str,
    today_snapshot: Dict[str, Any],
    yesterday_snapshot: Dict[str, Any],
    tech_stack: List[str],
    internet_facing: bool,
    rule_set_version: str = "2026.10",
) -> Dict[str, Any]:
    """
    Compute full SREI object.
    Safe with missing:
    - tech stack
    - CVSS
    - yesterday snapshot
    """

    yesterday_snapshot = yesterday_snapshot or {}

    stack_match = classify_stack_match(today_snapshot, tech_stack)
    chatter = compute_chatter(today_snapshot, yesterday_snapshot)
    feasibility = compute_feasibility(today_snapshot)
    kev_present = today_snapshot.get("kev") is not None

    priority = compute_priority(
        stack_match=stack_match,
        chatter_level=chatter["level"],
        feasibility=feasibility,
        internet_facing=internet_facing,
        kev_present=kev_present,
    )

    return {
        "cve_id": cve_id,
        "stack_match": stack_match,
        "chatter": chatter,
        "feasibility": feasibility,
        "priority": priority,
        "rule_set_version": rule_set_version,
        "timestamp_utc": utc_now_iso(),
        "stack_status": "no_stack_configured" if not tech_stack else "stack_configured",
    }
