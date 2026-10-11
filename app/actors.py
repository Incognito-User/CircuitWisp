# app/actors.py

from app.utils.logging import log_source_error

# Static mapping for now — later you can enrich from Mandiant, MITRE, CISA, etc.
ACTOR_MAP = {
    "CVE-2021-44228": [
        {
            "actor": "APT41",
            "type": "Nation-state threat actor",
            "disclaimer": "APT41 has been linked to cyber intrusions causing harm to organizations and individuals.",
            "campaigns": ["Log4Shell exploitation wave (2021-2022)"],
            "tooling": ["Web shells", "Custom backdoors"],
            "mitre_techniques": ["T1190", "T1133"],
            "target_sectors": ["Finance", "Government", "Technology"],
            "notes": "Observed exploiting vulnerable internet-facing systems shortly after public disclosure."
        },
        {
            "actor": "Conti Ransomware Group",
            "type": "Ransomware crew",
            "disclaimer": "Conti is responsible for significant harm, including ransomware attacks impacting critical infrastructure.",
            "campaigns": ["Initial access via Log4Shell"],
            "tooling": ["Cobalt Strike", "Ransomware payloads"],
            "mitre_techniques": ["T1059", "T1486"],
            "target_sectors": ["Healthcare", "Manufacturing"],
            "notes": "Used Log4Shell for rapid initial access during 2021-2022 campaigns."
        }
    ],

    "CVE-2020-1472": [
        {
            "actor": "Wizard Spider",
            "type": "Cybercrime group",
            "disclaimer": "Wizard Spider is associated with harmful ransomware operations.",
            "campaigns": ["Ryuk ransomware operations"],
            "tooling": ["TrickBot", "Ryuk"],
            "mitre_techniques": ["T1068", "T1482"],
            "target_sectors": ["Education", "Healthcare"],
            "notes": "Leveraged Zerologon for domain takeover."
        }
    ]
}


async def get_actor_mapping(cve_id: str):
    """
    Returns threat actor associations for a given CVE.
    Strictly harm-analysis focused, no operational details.
    """

    try:
        actors = ACTOR_MAP.get(cve_id.upper(), [])
        return {
            "cve_id": cve_id,
            "actors": actors,
            "count": len(actors)
        }
    except Exception as exc:
        log_source_error("actors", cve_id, exc)
        return {
            "cve_id": cve_id,
            "actors": [],
            "count": 0
        }

