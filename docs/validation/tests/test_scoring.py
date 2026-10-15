from datetime import datetime, timedelta

from app.models import ExploitRecord
from app.utils.scoring import score_exploit


def make_record(**kwargs):
    """Helper to create ExploitRecord with defaults."""
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


def test_score_exploit_range():
    """Scores must always be between 0 and 1."""
    record = make_record()
    score = score_exploit(record)
    assert 0 <= score <= 1


def test_score_exploit_recency_weighting():
    """Recent exploits should score higher than older ones."""
    recent = make_record(published=datetime.utcnow() - timedelta(days=1))
    old = make_record(published=datetime.utcnow() - timedelta(days=200))
    assert score_exploit(recent) > score_exploit(old)


def test_score_exploit_reliability_weighting():
    """Higher reliability should increase score."""
    low = make_record(reliability=0.1)
    high = make_record(reliability=0.9)
    assert score_exploit(high) > score_exploit(low)


def test_score_exploit_source_weighting():
    """Metasploit > ExploitDB > GitHub > RSS."""
    metasploit = make_record(source="metasploit")
    exploitdb = make_record(source="exploitdb")
    github = make_record(source="github")
    rss = make_record(source="rss")

    assert score_exploit(metasploit) > score_exploit(exploitdb)
    assert score_exploit(exploitdb) > score_exploit(github)
    assert score_exploit(github) > score_exploit(rss)


def test_score_exploit_maturity_weighting():
    """Full exploit should score higher than PoC."""
    poc = make_record(maturity="poc")
    full = make_record(maturity="full")
    assert score_exploit(full) > score_exploit(poc)


def test_score_exploit_vendor_confirmation():
    """Vendor-confirmed exploits should score higher."""
    unconfirmed = make_record(vendor_confirmed=False)
    confirmed = make_record(vendor_confirmed=True)
    assert score_exploit(confirmed) > score_exploit(unconfirmed)


def test_score_exploit_poc_bonus():
    """PoC availability should increase score."""
    no_poc = make_record(has_poc=False)
    yes_poc = make_record(has_poc=True)
    assert score_exploit(yes_poc) > score_exploit(no_poc)


def test_score_exploit_chatter_weighting():
    """More chatter should increase score."""
    quiet = make_record(chatter_count=0)
    noisy = make_record(chatter_count=50)
    assert score_exploit(noisy) > score_exploit(quiet)
