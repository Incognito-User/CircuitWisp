"""
External Attack Surface Module (EASM)
-------------------------------------

Graceful behavior:
    - No easm.json is baked into the tool.
    - If no inventory is provided via host-mounted file or env vars:
        visibility = "No visibility on External Attack Surface"
    - Global Shodan exposure is still evaluated.

This module does NOT call Shodan directly — it consumes results
from app/sources/shodan.py via service.py orchestration.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional
import json
import os


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class EASMInventory(BaseModel):
    domains: List[str] = Field(default_factory=list)
    ip_ranges: List[str] = Field(default_factory=list)
    cloud_assets: List[str] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    visibility: str = "No visibility on External Attack Surface"


class EASMExposure(BaseModel):
    exposed: bool
    assets: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    products: List[str] = Field(default_factory=list)
    severity: Optional[str] = None
    notes: Optional[str] = None
    visibility: str = "No visibility on External Attack Surface"


# ---------------------------------------------------------------------------
# Inventory Loader
# ---------------------------------------------------------------------------

def load_inventory() -> EASMInventory:
    """
    Loads EASM inventory from:
        - Host-mounted /app/config/easm.json
        - Environment variables

    If nothing is provided, returns:
        visibility = "No visibility on External Attack Surface"
    """

    inventory = EASMInventory()

    # 1. Host-mounted JSON file (not baked into image)
    json_path = "/app/config/easm.json"

    if os.path.exists(json_path):
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
                inventory = EASMInventory(**data)
                inventory.visibility = "Full visibility"
        except Exception:
            pass  # Silent fail — consistent with other modules

    # 2. Environment variable overrides
    domains = os.getenv("EASM_DOMAINS")
    ip_ranges = os.getenv("EASM_IP_RANGES")
    cloud_assets = os.getenv("EASM_CLOUD_ASSETS")

    if domains:
        inventory.domains.extend([d.strip() for d in domains.split(",")])
        inventory.visibility = "Partial visibility"

    if ip_ranges:
        inventory.ip_ranges.extend([r.strip() for r in ip_ranges.split(",")])
        inventory.visibility = "Partial visibility"

    if cloud_assets:
        inventory.cloud_assets.extend([c.strip() for c in cloud_assets.split(",")])
        inventory.visibility = "Partial visibility"

    return inventory


# ---------------------------------------------------------------------------
# Exposure Evaluation
# ---------------------------------------------------------------------------

def evaluate_exposure(
    snapshot: dict,
    shodan_results: List[dict],
    inventory: EASMInventory
) -> EASMExposure:
    """
    Evaluates external exposure even if inventory is empty.

    If inventory has no visibility:
        - Still evaluates global Shodan exposure
        - Marks visibility accordingly
    """

    exposed_assets = []
    exposed_ports = []
    exposed_products = []

    # Extract CVE-relevant products/ports
    cve_products = snapshot.get("products", [])
    cve_ports = snapshot.get("ports", [])

    # Evaluate each Shodan result
    for result in shodan_results:
        ip = result.get("ip_str")
        hostnames = result.get("hostnames", [])
        ports = result.get("ports", [])
        product = result.get("product")

        # Check IP range exposure (only if visibility exists)
        if inventory.ip_ranges and ip:
            if any(ip.startswith(prefix.split("/")[0]) for prefix in inventory.ip_ranges):
                exposed_assets.append(ip)

        # Check domain exposure
        if inventory.domains:
            for domain in inventory.domains:
                if domain in hostnames:
                    exposed_assets.append(domain)

        # Check product exposure
        if product and product in cve_products:
            exposed_products.append(product)

        # Check port exposure
        for port in ports:
            if port in cve_ports:
                exposed_ports.append(port)

    exposed = bool(exposed_assets or exposed_ports or exposed_products)

    severity = (
        "high" if exposed and exposed_ports else
        "medium" if exposed else
        "none"
    )

    return EASMExposure(
        exposed=exposed,
        assets=list(set(exposed_assets)),
        ports=list(set(exposed_ports)),
        products=list(set(exposed_products)),
        severity=severity,
        notes="Exposure detected via Shodan results" if exposed else "No external exposure detected",
        visibility=inventory.visibility
    )


# ---------------------------------------------------------------------------
# Snapshot Integration
# ---------------------------------------------------------------------------

def attach(snapshot: dict, exposure: EASMExposure) -> dict:
    """
    Adds EASM exposure results to the unified CVE snapshot.
    Called from heat.py.
    """
    snapshot["easm"] = exposure.dict()
    return snapshot
