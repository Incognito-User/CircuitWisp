from datetime import datetime, timedelta

from app.models import ExploitRecord
from app.scoring import score_exploit


def test_score_exploit_range():
    """Scores must always be between 0 and 1."""
    record = ExploitRecord(
        source="exploitdb",
        cve_id="CVE-2024-12345",
        title="Test exploit",
        url="https://example.com",
        published=datetime.utcnow(),
        reliability=0.9,
    )

    score = score_exploit(record)
    assert 0 <= score <= 1


def test_score_exploit_recency_weighting():
    """Recent exploits should score higher than older ones."""
    recent = ExploitRecord(
        source="github",
        cve_id="CVE-2024-12345",
        title="Recent exploit",
        url="https://example.com",
        published=datetime.utcnow() - timedelta(days=1),
        reliability=0.5,
    )

    old = ExploitRecord(
        source="github",
        cve_id="CVE-2024-12345",
        title="Old exploit",
        url="https://example.com",
        published=datetime.utcnow() - timedelta(days=200),
        reliability=0.5,
    )

    assert score_exploit(recent) > score_exploit(old)
