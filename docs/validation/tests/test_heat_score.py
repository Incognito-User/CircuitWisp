from datetime import datetime, timedelta

from app.models import ExploitRecord
from app.utils.heat import heat_score


def make_record(**kwargs):
    return ExploitRecord(
        source=kwargs.get("source", "exploitdb"),
        cve_id=kwargs.get("cve_id", "CVE-2024-12345"),
        title=kwargs.get("title", "Test exploit"),
        url=kwargs.get("url", "https://example.com"),
        published=kwargs.get("published", datetime.utcnow()),
        reliability=kwargs.get("reliability", 0.5),
        maturity=kwargs.get("maturity", "poc"),
        vendor_confirmed=kwargs.get("vendor_confirmed", False),
        has_poc=kwargs.get("has_poc", False),
        chatter_count=kwargs.get("chatter_count", 0),
    )


def test_heat_score_range():
    """Heat score must always be between 0 and 1."""
    record = make_record()
    score = heat_score(record)
    assert 0 <= score <= 1


def test_heat_score_recency_bonus():
    """Recent exploits should have higher heat."""
    recent = make_record(published=datetime.utcnow() - timedelta(days=1))
    old = make_record(published=datetime.utcnow() - timedelta(days=200))
    assert heat_score(recent) > heat_score(old)


def test_heat_score_vendor_confirmation():
    """Vendor confirmation should increase heat."""
    unconfirmed = make_record(vendor_confirmed=False)
    confirmed = make_record(vendor_confirmed=True)
    assert heat_score(confirmed) > heat_score(unconfirmed)


def test_heat_score_chatter():
    """Chatter should increase heat."""
    quiet = make_record(chatter_count=0)
    noisy = make_record(chatter_count=100)
    assert heat_score(noisy) > heat_score(quiet)
