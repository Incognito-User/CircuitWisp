import pytest

from app.sources.exploitdb import fetch_exploitdb
from app.sources.github import fetch_github
from app.models import ExploitRecord


@pytest.mark.asyncio
async def test_exploitdb_returns_list():
    """ExploitDB fetch should always return a list, even on failure."""
    results = await fetch_exploitdb("CVE-2024-12345")
    assert isinstance(results, list)

    # If results exist, they must be ExploitRecord objects
    if results:
        assert isinstance(results[0], ExploitRecord)


@pytest.mark.asyncio
async def test_github_returns_list():
    """GitHub fetch should always return a list, even on failure."""
    results = await fetch_github("CVE-2024-12345")
    assert isinstance(results, list)

    # If results exist, they must be ExploitRecord objects
    if results:
        assert isinstance(results[0], ExploitRecord)
