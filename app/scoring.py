from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Normalization helper
# ---------------------------------------------------------------------------

def normalize(value, max_value):
    if max_value == 0:
        return 0.0
    return max(0.0, min(1.0, value / max_value))


class latest_published:
    """
    Utility wrapper for handling the newest publication timestamp in a record set.

    This class normalizes timestamps to UTC, computes age in days, and exposes
    a simple recency bonus suitable for the heat-score heuristics used here.
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

    def __bool__(self) -> bool:
        return self.value is not None

    def __float__(self) -> float:
        return self.recency_bonus()


# ---------------------------------------------------------------------------
# 1️⃣ Updated scoring model (weight Metasploit more heavily)
# ---------------------------------------------------------------------------

def exploitation_maturity_score(records):
    """
    Weighted exploitation maturity:
    - Metasploit modules get highest weight
    - ExploitDB + GitHub PoCs get medium weight
    - Vendor + RSS get low weight
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
# 2️⃣ Updated exploit_maturity (detect weaponization)
# ---------------------------------------------------------------------------

def exploit_maturity(records) -> float:
    """
    0.0–1.0 scale:
    - 0.8+ weaponized (Metasploit exploit modules, ExploitDB exploits)
    - 0.5+ PoCs (GitHub PoCs, ExploitDB PoCs)
    - <0.3 low maturity
    """
    if not records:
        return 0.0

    score = 0.0

    for r in records:
        src = r.source.lower()
        title = r.title.lower()
        url = r.url.lower()

        # Weaponized exploit indicators
        if src == "metasploit" and "modules/exploits" in url:
            score += 1.0
        elif src == "exploitdb" and "exploit" in title:
            score += 0.9

        # PoC indicators
        elif src == "github" and any(
            kw in title for kw in ["poc", "exploit", "proof of concept", "weaponized"]
        ):
            score += 0.7
        elif src == "exploitdb":
            score += 0.6

        # Vendor-only / chatter-only
        else:
            score += 0.2

    return normalize(score, max_value=len(records))


# ---------------------------------------------------------------------------
# 3️⃣ Updated poc_available (detect GitHub PoCs more accurately)
# ---------------------------------------------------------------------------

def poc_available(records) -> bool:
    """
    True if any record looks like a PoC or exploit.
    """
    for r in records:
        src = r.source.lower()
        title = r.title.lower()
        url = r.url.lower()

        # Metasploit or ExploitDB = definitely PoC/exploit
        if src in {"metasploit", "exploitdb"}:
            return True

        # GitHub PoC detection
        if src == "github":
            if any(kw in title for kw in ["poc", "exploit", "proof of concept", "weaponized"]):
                return True
            if any(kw in url for kw in ["poc", "exploit"]):
                return True

    return False


# ---------------------------------------------------------------------------
# 4️⃣ Updated vendor_confirmed (detect MSRC/Cisco/Oracle advisories)
# ---------------------------------------------------------------------------

def vendor_confirmed(records) -> bool:
    """
    True if any vendor advisory is present.
    """
    vendor_sources = {
        "vendor", "msrc", "cisco", "redhat", "ubuntu", "debian",
        "vmware", "oracle", "adobe", "intel"
    }

    for r in records:
        if r.source.lower() in vendor_sources:
            return True

    return False


# ---------------------------------------------------------------------------
# Heat score (legacy-compatible)
# ---------------------------------------------------------------------------

def heat_score(
    exploit_maturity: float,
    poc_available: bool,
    vendor_confirmed: bool,
    chatter_count: int,
    latest_published: datetime | None,
):
    """
    Legacy-compatible heat score.
    You can replace this later with exploitation_maturity_score(),
    chatter_volume_score(), vendor_presence_score(), recency_activity_score().
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
        latest_pub = globals()["latest_published"](latest_published)
        base += latest_pub.recency_bonus()

    return max(0.0, min(1.0, base))


# ---------------------------------------------------------------------------
# Risk level
# ---------------------------------------------------------------------------

def risk_level(score: float) -> str:
    if score >= 0.8:
        return "Critical"
    if score >= 0.6:
        return "High"
    if score >= 0.4:
        return "Medium"
    if score >= 0.2:
        return "Low"
    return "Informational"

def score_exploit(record):
    """
    Compatibility wrapper for legacy code.
    Uses exploit_maturity() heuristics on a single record.
    """
    src = record.source.lower()
    title = record.title.lower()
    url = record.url.lower()

    # Weaponized
    if src == "metasploit" and "modules/exploits" in url:
        return 0.95
    if src == "exploitdb" and "exploit" in title:
        return 0.9

    # PoC
    if src == "github" and any(
        kw in title for kw in ["poc", "exploit", "proof of concept", "weaponized"]
    ):
        return 0.85

    # Vendor advisory
    vendor_sources = {
        "vendor", "msrc", "cisco", "redhat", "ubuntu", "debian",
        "vmware", "oracle", "adobe", "intel"
    }
    if src in vendor_sources:
        return 0.75

    # RSS chatter
    if src == "rss":
        return 0.6

    # Default
    return 0.5
