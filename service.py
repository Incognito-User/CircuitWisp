from app.sources.exploitdb import fetch_exploitdb
from app.sources.github import fetch_github

async def gather_exploits(cve_id: str):
    results = []
    results.extend(await fetch_exploitdb(cve_id))
    results.extend(await fetch_github(cve_id))
    return results
