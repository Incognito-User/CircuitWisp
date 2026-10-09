import asyncio
from datetime import datetime
from typing import List, Dict, Any

from app.models import ExploitRecord
from app.scoring import (
    exploit_maturity,
    poc_available,
    vendor_confirmed,
    heat_score,
    risk_level,
)

# Existing exploit sources
from sources.exploitdb import fetch_exploitdb
from sources.github import fetch_github
from sources.metasploit import fetch_metasploit
from sources.vendor import fetch_vendor_advisories
from sources.rss import fetch_rss_chatter

# New intel sources
from sources.epss import fetch_epss
from sources.kev import fetch_kev
from sources.nvd import fetch_nvd
from sources.greynoise import fetch_greynoise
from sources.shodan import fetch_shodan


# ---------------------------------------------------------------------------
# Gather all exploit-related sources
# ---------------------------------------------------------------------------

async def gather_exploits(cve_id: str) -> Dict[str, Any]:
    """
    Collect exploit records + intel signals for a CVE.
    Returns a dict containing:
        - exploits (list[ExploitRecord])
        - epss, kev, nvd, greynoise, shodan (dicts)
    """

    edb_task = asyncio.create_task(fetch_exploitdb(cve_id))
    gh_task = asyncio.create_task(fetch_github(cve_id))
    ms_task = asyncio.create_task(fetch_metasploit(cve_id))
    vendor_task = asyncio.create_task(fetch_vendor_advisories(cve_id))
    rss_task = asyncio.create_task(fetch_rss_chatter(cve_id))

    epss_task = asyncio.create_task(fetch_epss(cve_id))
    kev_task = asyncio.create_task(fetch_kev(cve_id))
    nvd_task = asyncio.create_task(fetch_nvd(cve_id))
    gn_task = asyncio.create_task(fetch_greynoise(cve_id))
    shodan_task = asyncio.create_task(fetch_shodan(cve_id))

    (
        edb,
        gh,
        ms,
        vendor,
        rss,
        epss,
        kev,
        nvd,
        greynoise,
        shodan,
    ) = await asyncio.gather(
        edb_task,
        gh_task,
        ms_task,
        vendor_task,
        rss_task,
        epss_task,
        kev_task,
        nvd_task,
        gn_task,
        shodan_task,
    )

    exploits: List[ExploitRecord] = []
    for group in (edb, gh, ms, vendor, rss):
        if group:
            exploits.extend(group)

    return {
        "exploits": exploits,
        "epss": epss,
        "kev": kev,
        "nvd": nvd,
        "greynoise": greynoise,
        "shodan": shodan,
    }


# ---------------------------------------------------------------------------
# Build snapshot
# ---------------------------------------------------------------------------

async def build_snapshot(cve_id: str) -> Dict[str, Any]:
    data = await gather_exploits(cve_id)

    exploits = data["exploits"]
    epss = data["epss"]
    kev = data["kev"]
    nvd = data["nvd"]
    greynoise = data["greynoise"]
    shodan = data["shodan"]

    # Basic scoring inputs
    maturity = exploit_maturity(exploits)
    poc = poc_available(exploits)
    vendor_conf = vendor_confirmed(exploits)
    chatter_count = sum(1 for r in exploits if r.source == "rss")
    latest_published = max((r.published for r in exploits), default=None)

    # Heat score (legacy-compatible)
    base_heat = heat_score(
        exploit_maturity=maturity,
        poc_available=poc,
        vendor_confirmed=vendor_conf,
        chatter_count=chatter_count,
        latest_published=latest_published,
    )

    # Enhanced heat model
    epss_score = epss.get("epss") or 0
    kev_present = kev is not None
    cvss_v3 = nvd.get("cvss_v3") or 0
    greynoise_ips = greynoise.get("ip_count") or 0
    shodan_exposure = shodan.get("exposure_count") or 0

    enhanced_heat = 0
    if kev_present:
        enhanced_heat += 0.30

    enhanced_heat += epss_score * 0.25
    enhanced_heat += maturity * 0.25
    enhanced_heat += min(greynoise_ips / 100, 1.0) * 0.20
    enhanced_heat += min(shodan_exposure / 500, 1.0) * 0.15
    enhanced_heat += (cvss_v3 / 10) * 0.10
    enhanced_heat += min(chatter_count / 20, 1.0) * 0.10

    final_heat = max(base_heat, enhanced_heat)
    level = risk_level(final_heat)

    return {
        "cve_id": cve_id,
        "exploits": [r.to_dict() for r in exploits],
        "epss": epss,
        "kev": kev,
        "nvd": nvd,
        "greynoise": greynoise,
        "shodan": shodan,
        "heat": final_heat,
        "risk_level": level,
        "latest_published": latest_published.isoformat() if latest_published else None,
    }


# ---------------------------------------------------------------------------
# Build timeline
# ---------------------------------------------------------------------------

async def build_timeline(cve_id: str) -> List[Dict[str, Any]]:
    data = await gather_exploits(cve_id)

    timeline = []

    # Exploit records
    for r in data["exploits"]:
        timeline.append({
            "date": r.published.isoformat(),
            "source": r.source,
            "title": r.title,
            "url": r.url,
            "type": "exploit",
        })

    # KEV
    if data["kev"]:
        timeline.append({
            "date": data["kev"]["date_added"],
            "source": "kev",
            "title": "Added to CISA KEV",
            "url": None,
            "type": "kev",
        })

    # EPSS
    if data["epss"].get("date"):
        timeline.append({
            "date": data["epss"]["date"],
            "source": "epss",
            "title": f"EPSS score: {data['epss']['epss']}",
            "url": None,
            "type": "epss",
        })

    # NVD publication
    if data["nvd"].get("description"):
        timeline.append({
            "date": datetime.utcnow().isoformat(),
            "source": "nvd",
            "title": "NVD data available",
            "url": None,
            "type": "nvd",
        })

    # GreyNoise exploitation
    if data["greynoise"].get("ip_count"):
        timeline.append({
            "date": datetime.utcnow().isoformat(),
            "source": "greynoise",
            "title": f"GreyNoise exploitation activity: {data['greynoise']['ip_count']} IPs",
            "url": None,
            "type": "greynoise",
        })

    # Shodan exposure
    if data["shodan"].get("exposure_count"):
        timeline.append({
            "date": datetime.utcnow().isoformat(),
            "source": "shodan",
            "title": f"Shodan exposure: {data['shodan']['exposure_count']} hosts",
            "url": None,
            "type": "shodan",
        })

    return sorted(timeline, key=lambda x: x["date"])
