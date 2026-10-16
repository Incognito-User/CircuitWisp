# app/service.py
# ---------------------------------------------------------------------------
# SERVICE LAYER — CORE SNAPSHOT ENGINE
# Provides unified CVE intelligence aggregation, scoring, timeline generation,
# and SREI enrichment.
# ---------------------------------------------------------------------------

import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any

def ensure_aware(dt: datetime) -> datetime:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

from app.models import ExploitRecord

# Scoring + SREI + Tech Stack
from app.utils.scoring import (
    exploit_maturity,
    poc_available,
    vendor_confirmed,
    heat_score,
    risk_level,
)
from app.utils.srei import compute_srei
from app.utils.techstack import load_tech_stack

# Exploit + PoC + Vendor + RSS
from app.sources.exploitdb import fetch_exploitdb
from app.sources.github import fetch_github
from app.sources.metasploit import fetch_metasploit
from app.sources.vendor import fetch_vendor_advisories
from app.sources.rss import fetch_rss_chatter

# EPSS + KEV + NVD + GreyNoise + Shodan
from app.sources.epss import fetch_epss
from app.sources.kev import fetch_kev
from app.sources.nvd import fetch_nvd
from app.sources.greynoise import fetch_greynoise
from app.sources.shodan import fetch_shodan

# MITRE + CISA Campaigns
from app.sources.mitre import fetch_mitre_intrusion_sets
from app.sources.cisa_campaigns import fetch_cisa_campaigns

# EASM
from app.utils.easm import load_inventory, evaluate_exposure, attach as attach_easm

# ---------------------------------------------------------------------------
# Gather all exploit-related intelligence for a CVE
# ---------------------------------------------------------------------------
async def gather_exploits(cve_id: str) -> Dict[str, Any]:

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

    mitre_task = asyncio.create_task(fetch_mitre_intrusion_sets())
    cisa_task = asyncio.create_task(fetch_cisa_campaigns())

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
        mitre,
        cisa,
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
        mitre_task,
        cisa_task,
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
        "mitre": mitre,
        "cisa": cisa,
    }


# ---------------------------------------------------------------------------
# Build unified CVE snapshot
# ---------------------------------------------------------------------------
async def build_snapshot(cve_id: str) -> Dict[str, Any]:

    data = await gather_exploits(cve_id)

    exploits = data["exploits"]
    epss = data["epss"]
    kev = data["kev"]
    nvd = data["nvd"]
    greynoise = data["greynoise"]
    shodan = data["shodan"]
    mitre = data["mitre"]
    cisa = data["cisa"]

    maturity = exploit_maturity(exploits)
    poc = poc_available(exploits)
    vendor_conf = vendor_confirmed(exploits)
    chatter_count = sum(1 for r in exploits if r.source == "rss")

    latest_published = max(
        (ensure_aware(r.published) for r in exploits),
        default=None
    )

    base_heat = heat_score(
        exploit_maturity=maturity,
        poc_available=poc,
        vendor_confirmed=vendor_conf,
        chatter_count=chatter_count,
        latest_published=latest_published,
    )

    epss_score = epss.get("epss") or 0
    kev_present = kev is not None

    cvss_raw = nvd.get("cvss_v3") or 0
    cvss_v3 = cvss_raw.get("baseScore") if isinstance(cvss_raw, dict) else cvss_raw
    cvss_v3 = cvss_v3 or 0

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

    # -----------------------------------------------------------------------
    # Filter MITRE + CISA by CVE
    # -----------------------------------------------------------------------
    mitre_filtered = [
        group for group in mitre
        if cve_id in group.get("associated_cves", [])
    ]

    cisa_filtered = [
        entry for entry in cisa
        if cve_id in entry.get("cves", [])
    ]

    snapshot = {
        "cve_id": cve_id,
        "exploits": [r.to_dict() for r in exploits],
        "epss": epss,
        "kev": kev,
        "nvd": nvd,
        "greynoise": greynoise,
        "shodan": shodan,
        "mitre_groups": mitre_filtered,
        "cisa_campaigns": cisa_filtered,
        "heat": final_heat,
        "risk_level": level,
        "latest_published": latest_published.isoformat() if latest_published else None,
    }

    tech_stack = load_tech_stack()
    srei = compute_srei(
        cve_id=cve_id,
        today_snapshot=snapshot,
        yesterday_snapshot={},
        tech_stack=tech_stack,
        internet_facing=False,
    )

    snapshot["srei"] = srei

    return snapshot


# ---------------------------------------------------------------------------
# Build CVE Timeline
# ---------------------------------------------------------------------------
async def build_timeline(cve_id: str) -> List[Dict[str, Any]]:

    data = await gather_exploits(cve_id)

    exploits = data["exploits"]
    kev = data["kev"]
    nvd = data["nvd"]

    timeline: List[Dict[str, Any]] = []

    for r in exploits:
        if r.published:
            timeline.append({
                "type": "exploit",
                "source": r.source,
                "title": r.title,
                "timestamp": r.published,
                "url": r.url,
            })

    if kev and kev.get("dateAdded"):
        timeline.append({
            "type": "kev",
            "source": "cisa",
            "title": kev.get("shortDescription", "KEV Entry"),
            "timestamp": kev["dateAdded"],
            "url": "",
        })

    if nvd and nvd.get("published"):
        timeline.append({
            "type": "nvd",
            "source": "nvd",
            "title": "NVD Publication",
            "timestamp": nvd["published"],
            "url": "",
        })

    for r in exploits:
        if r.source == "rss" and r.published:
            timeline.append({
                "type": "chatter",
                "source": "rss",
                "title": r.title,
                "timestamp": r.published,
                "url": r.url,
            })

    def safe_dt(ts):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.min

    timeline.sort(key=lambda x: safe_dt(x["timestamp"]))

    return timeline
