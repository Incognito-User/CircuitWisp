from app.sources.exploitdb import fetch_exploitdb
from app.sources.github import fetch_github
from app.models import ExploitRecord
from app.scoring import score_exploit


async def gather_exploits(cve_id: str) -> list[ExploitRecord]:
    """Fetch and correlate exploits across all sources for a CVE."""
    exploits: list[ExploitRecord] = []

    edb = await fetch_exploitdb(cve_id)
    gh = await fetch_github(cve_id)

    exploits.extend(edb)
    exploits.extend(gh)

    # Future: add metasploit, vendor advisories, RSS, etc.

    # Attach scores
    for record in exploits:
        record_score = score_exploit(record)
        # you can later wrap this into a richer object if needed

    return exploits
