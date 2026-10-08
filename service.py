from typing import List

import asyncio

from sources.exploitdb import fetch_exploitdb
from sources.github import fetch_github
from sources.metasploit import fetch_metasploit
from sources.vendor import fetch_vendor_advisories
from sources.rss import fetch_rss_chatter


class ExploitActivitySnapshot:
    """
    Unified view of exploit activity for a given CVE.
    Contains scored records and simple aggregate metrics.
    """

    def __init__(self, cve_id: str, records: List[ExploitRecord]):
        self.cve_id = cve_id
        self.records = records
        self.total = len(records)
        self.by_source = self._group_by_source()

    def _group_by_source(self) -> dict:
        counts: dict[str, int] = {}
        for r in self.records:
            src = r.source.lower()
            counts[src] = counts.get(src, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "total": self.total,
            "by_source": self.by_source,
            "records": [
                {
                    "source": r.source,
                    "cve_id": r.cve_id,
                    "title": r.title,
                    "url": r.url,
                    "published": r.published.isoformat(),
                    "score": score_exploit(r),
                }
                for r in self.records
            ],
        }


async def gather_exploits(cve_id: str) -> ExploitActivitySnapshot:
    """
    Fetch and correlate exploits across all sources for a CVE,
    score them, and return a unified activity snapshot.
    """

    # Run all sources concurrently
    edb_task = fetch_exploitdb(cve_id)
    gh_task = fetch_github(cve_id)
    ms_task = fetch_metasploit(cve_id)
    vendor_task = fetch_vendor_advisories(cve_id)
    rss_task = fetch_rss_chatter(cve_id)

    edb, gh, ms, vendor, rss = await asyncio.gather(
        edb_task, gh_task, ms_task, vendor_task, rss_task
    )

    # Merge all records
    records: List[ExploitRecord] = []
    records.extend(edb)
    records.extend(gh)
    records.extend(ms)
    records.extend(vendor)
    records.extend(rss)

    # Sort by score (desc) then recency
    records.sort(
        key=lambda r: (score_exploit(r), r.published),
        reverse=True,
    )

    return ExploitActivitySnapshot(cve_id=cve_id, records=records)
