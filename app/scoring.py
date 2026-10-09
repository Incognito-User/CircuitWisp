from datetime import datetime, timedelta
from app.models import ExploitRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_reliability(value) -> float:
    """Clamp reliability to [0.0, 1.0] and ensure numeric type."""
    try:
        val = float(value)
    except Exception:
        val = 0.5
    return max(0.0, min(1.0, val))


def _safe_datetime(dt) -> datetime:
    """Ensure published timestamps are valid datetimes."""
    if isinstance(dt, datetime):
        return dt
    try:
        return datetime.fromisoformat(str(dt).replace("Z", "+00:00"))
    except Exception:
        return datetime.utcnow()


# ---------------------------------------------------------------------------
# Base Exploit Scoring (used in /cve and /snapshot)
# ---------------------------------------------------------------------------

def score_exploit(record: ExploitRecord) -> float:
    """
    Deterministic scoring:
    - base on reliability
    - boost for recency
    - adjust by source confidence
    """

    base = _safe_reliability(record.reliability)
    source_weight = _source_weight(record.source)
    recency_weight = _recency_weight(_safe_datetime(record.published))

    score = base * source_weight * recency_weight
    return round(min(score, 1.0), 3)


def _source_weight(source: str) -> float:
    weights = {
        "exploitdb": 1.0,
        "github": 0.8,
        "metasploit": 1.0,
        "vendor": 0.9,
        "rss": 0.6,
    }
    return weights.get(source.lower(), 0.5)


def _recency_weight(published: datetime) -> float:
    days = max(0, (datetime.utcnow() - published).days)
    if days <= 1:
        return 1.0
    if days <= 7:
        return 0.9
    if days <= 30:
        return 0.8
    if days <= 180:
        return 0.7
    return 0.5


# ---------------------------------------------------------------------------
# Heat Score Components (used in /heat)
# ---------------------------------------------------------------------------

def exploit_maturity(records: list[ExploitRecord]) -> float:
    """
    Returns a maturity score between 0.0 and 1.0 based on exploit development.
    Hardened to avoid false positives.
    """

    has_exploitdb = any(r.source.lower() == "exploitdb" for r in records)
    has_github_poc = any(r.source.lower() == "github" for r in records)
    has_metasploit = any(r.source.lower() == "metasploit" for r in records)

    # Tightened exploit keyword detection
    exploitation_keywords = ["poc", "proof-of-concept", "weaponized", "metasploit"]
    has_exploitation_mention = any(
        any(kw in (r.title.lower() + r.url.lower()) for kw in exploitation_keywords)
        for r in records
    )

    maturity = 0.0

    if has_exploitdb or has_github_poc:
        maturity = max(maturity, 0.3)
    if has_metasploit:
        maturity = max(maturity, 0.6)
    if has_exploitation_mention:
        maturity = max(maturity, 1.0)

    return maturity


def vendor_confirmed(records: list[ExploitRecord]) -> bool:
    vendor_sources = {
        "vendor", "msrc", "cisco", "redhat", "ubuntu", "debian", "vmware"
    }
    return any(r.source.lower() in vendor_sources for r in records)


def poc_available(records: list[ExploitRecord]) -> bool:
    poc_sources = {"github", "exploitdb", "metasploit"}
    return any(r.source.lower() in poc_sources for r in records)


# ---------------------------------------------------------------------------
# Heat Score (0–100)
# ---------------------------------------------------------------------------

def heat_score(
    exploit_maturity: float,
    poc_available: bool,
    vendor_confirmed: bool,
    chatter_count: int,
    latest_published: datetime,
) -> int:

    latest_published = _safe_datetime(latest_published)
    score = 0

    score += int(exploit_maturity * 30)

    if poc_available:
        score += 25

    if vendor_confirmed:
        score += 20

    if chatter_count > 10:
        score += 15
    elif chatter_count > 3:
        score += 10
    elif chatter_count > 0:
        score += 5

    days = max(0, (datetime.utcnow() - latest_published).days)
    if days <= 7:
        score += 10
    elif days <= 30:
        score += 5

    return min(score, 100)


# ---------------------------------------------------------------------------
# Risk Level (human-friendly severity)
# ---------------------------------------------------------------------------

def risk_level(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"
