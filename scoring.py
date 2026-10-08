from datetime import datetime, timedelta
from app.models import ExploitRecord


def score_exploit(record: ExploitRecord) -> float:
    """
    Deterministic scoring:
    - base on reliability
    - boost for recency
    - adjust by source confidence
    """
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
