# app/scoring.py
# ---------------------------------------------------------------------------
# SCORING ENGINE
# Provides exploit maturity scoring, PoC detection, vendor confirmation,
# legacy heat scoring, and risk level classification.
# ---------------------------------------------------------------------------

from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Normalization Helper
# ---------------------------------------------------------------------------
def normalize(value, max_value):
    """Normalize a value to 0.0–1.0 range based on max_value."""
    if max_value == 0:
        return 0.0
    return max(0.0, min(1.0, value / max_value))


# ---------------------------------------------------------------------------
# Latest Published Timestamp Wrapper
# ---------------------------------------------------------------------------
class latest_published:
    """
    Utility wrapper for handling newest publication timestamp.
    Provides UTC normalization, age calculation, and recency bonus.
    """

    def __init__(self, value: datetime | None):
        self.value = value

    def as_utc(self) -> datetime | None:
        if self.value is None:
            return None
        if self.value.tzinfo is None:
            return self.value.replace(tzinfo=timezone.utc)
        return self.value.astimezone(timezone.utc)

    def age_days(self) -> int:
        dt = self.as_utc()
        if dt is None:
            return 999999
        return (datetime.now(timezone.utc) - dt).days

    def recency_bonus(self) -> float:
        age = self.age_days()
        if age <= 7:
            return 0.15
        if age <= 30:
            return 0.08
        return 0.0

    def __bool__(self):
        return self.value is not None

    def __float__(self):
        return self.recency_bonus()


# ---------------------------------------------------------------------------
# Exploitation Maturity Score (Weighted)
# ---------------------------------------------------------------------------
def exploitation_maturity_score(records):
    """
    Weighted exploitation maturity:
    - Metasploit: highest weight
    - ExploitDB + GitHub: medium weight
    - Vendor + RSS: low weight
    """
    if not records:
        return 0.0

    score = 0.0

    for r in records:
        src = r.source.lower()
        base = r.reliability

        if src == "metasploit":
            score += base * 1.3
        elif src in {"exploitdb", "github"}:
            score += base * 1.1
        else:
            score += base * 0.7

    return normalize(score, max_value=len(records))


# ---------------------------------------------------------------------------
# Exploit Maturity (Heuristic)
# ---------------------------------------------------------------------------
def exploit_maturity(records) -> float:
    """
    0.0–1.0 scale:
    - 0.8+ weaponized
    - 0.5+ PoCs
    - <0.3 low maturity
    """
    if not records:
        return 0.0

    score = 0.0

    for r in records:
        src = r.source.lower()
        title = r.title.lower()
        url = r.url.lower()

        # Weaponized
        if src == "metasploit" and "modules/exploits" in url:
            score += 1.0
        elif src == "exploitdb" and "exploit" in title:
            score += 0.9

        # PoCs
        elif src == "github" and any(
            kw in title for kw in ["poc", "exploit", "proof of concept", "weaponized"]
        ):
            score += 0.7
        elif src == "exploitdb":
            score += 0.6

        # Vendor / RSS
        else:
            score += 0.2

    return normalize(score, max_value=len(records))


# ---------------------------------------------------------------------------
# PoC Availability Detection
# ---------------------------------------------------------------------------
def poc_available(records) -> bool:
    """Return True if any record looks like a PoC or exploit."""
    for r in records:
        src = r.source.lower()
        title = r.title.lower()
        url = r.url.lower()

        if src in {"metasploit", "exploitdb"}:
            return True

        if src == "github":
            if any(kw in title for kw in ["poc", "exploit", "proof of concept", "weaponized"]):
                return True
            if any(kw in url for kw in ["poc", "exploit"]):
                return True

    return False


# ---------------------------------------------------------------------------
# Vendor Confirmation Detection
# ---------------------------------------------------------------------------
def vendor_confirmed(records) -> bool:
    """Return True if any vendor advisory is present."""
    vendor_sources = {
        "vendor", "msrc", "cisco", "redhat", "ubuntu", "debian",
        "vmware", "oracle", "adobe", "intel"
    }

    return any(r.source.lower() in vendor_sources for r in records)


# ---------------------------------------------------------------------------
# Legacy Heat Score
# ---------------------------------------------------------------------------
def heat_score(
    exploit_maturity: float,
    poc_available: bool,
    vendor_confirmed: bool,
    chatter_count: int,
    latest_published: datetime | None,
):
    """
    Legacy heat score model.
    Adds PoC, vendor, chatter, and recency bonuses.
    """

    base = exploit_maturity

    if poc_available:
        base += 0.15
    if vendor_confirmed:
        base += 0.15
    if chatter_count > 10:
        base += 0.15
    elif chatter_count > 3:
        base += 0.08

    if latest_published is not None:
        lp = latest_published(latest_published)
        base += lp.recency_bonus()

    return max(0.0, min(1.0, base))


# ---------------------------------------------------------------------------
# Risk Level Classification
# ---------------------------------------------------------------------------
def risk_level(score: float) -> str:
    """Map heat score to risk level."""
    if score >= 0.8:
        return "Critical"
    if score >= 0.6:
        return "High"
    if score >= 0.4:
        return "Medium"
    if score >= 0.2:
        return "Low"
    return "Informational"


# ---------------------------------------------------------------------------
# Single-Record Exploit Score (Legacy)
# ---------------------------------------------------------------------------
def score_exploit(record):
    """Compatibility wrapper for legacy scoring."""
    src = record.source.lower()
    title = record.title.lower()
    url = record.url.lower()

    if src == "metasploit" and "modules/exploits" in url:
        return 0.95
    if src == "exploitdb" and "exploit" in title:
        return 0.9

    if src == "github" and any(
        kw in title for kw in ["poc", "exploit", "proof of concept", "weaponized"]
    ):
        return 0.85

    vendor_sources = {
        "vendor", "msrc", "cisco", "redhat", "ubuntu", "debian",
        "vmware", "oracle", "adobe", "intel"
    }
    if src in vendor_sources:
        return 0.75

    if src == "rss":
        return 0.6

    return 0.5
