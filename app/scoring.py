from datetime import datetime, timedelta
from app.models import ExploitRecord


def score_exploit(record: ExploitRecord) -> float:
    base = record.reliability or 0.5
    source_weight = _source_weight(record.source)
    recency_weight = _recency_weight(record.published)
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
    days = (datetime.utcnow() - published).days
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
# Heat Score Components
# ---------------------------------------------------------------------------

def exploit_maturity(records: list[ExploitRecord]) -> float:
    has_exploitdb = any(r.source == "exploitdb" for r in records)
    has_github_poc = any(r.source == "github" for r in records)
    has_metasploit = any(r.source == "metasploit" for r in records)
    has_exploitation_mention = any(
        "exploit" in (r.title.lower() + r.url.lower())
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
# Heat Score
# ---------------------------------------------------------------------------

def heat_score(
    exploit_maturity: float,
    poc_available: bool,
    vendor_confirmed: bool,
    chatter_count: int,
    latest_published: datetime,
) -> int:
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

    if latest_published:
        days = (datetime.utcnow() - latest_published).days
        if days <= 7:
            score += 10
        elif days <= 30:
            score += 5

    return min(score, 100)
