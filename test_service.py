import pytest

from app.service import gather_exploits


@pytest.mark.asyncio
async def test_gather_exploits_runs():
    """Correlation engine should run without errors and return a list."""
    results = await gather_exploits("CVE-2024-12345")
    assert isinstance(results, list)
