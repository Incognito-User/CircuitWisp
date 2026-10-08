import pytest

from app.sources.exploitdb import fetch_exploitdb
from app.sources.github import fetch_github


@pytest.mark.asyncio
async def test_exploitdb_returns_list():
    """ExploitDB fetch should always return a list, even on failure."""
    results = await fetch_exploitdb("CVE-2024-12345")
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_github_returns_list():
    """GitHub fetch should always return a list, even on failure."""
    results = await fetch_github("CVE-2024-12345")
    assert isinstance(results, list)
