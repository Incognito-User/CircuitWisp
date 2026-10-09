from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Normalization helper
# ---------------------------------------------------------------------------

def normalize(value, max_value):
    if max_value == 0:
        return 0.0
    return max(0.0, min(1.0, value / max_value))


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

    if latest_published:
        days = (datetime.utcnow() - latest_published).days
        if days <= 7:
            base += 0.15
        elif days <= 30:
            base += 0.08

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
