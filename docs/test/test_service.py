import pytest

from app.utils.service import gather_exploits
from app.utils.service import ExploitActivitySnapshot


@pytest.mark.asyncio
async def test_gather_exploits_runs():
    """Correlation engine should run without errors and return a snapshot object."""
    snapshot = await gather_exploits("CVE-2024-12345")

    # Correct return type
    assert isinstance(snapshot, ExploitActivitySnapshot)

    # Snapshot must contain a list of records
    assert isinstance(snapshot.records, list)

    # Snapshot must contain metadata
    assert snapshot.cve_id == "CVE-2024-12345"

    # Records must be sorted by score (desc) then recency
    if len(snapshot.records) >= 2:
        scores = [r.score for r in snapshot.to_dict()["records"]]
        assert scores == sorted(scores, reverse=True)
