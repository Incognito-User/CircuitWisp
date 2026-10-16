from datetime import datetime, timedelta

def normalize(value, max_value):
    if max_value == 0:
        return 0.0
    return max(0.0, min(1.0, value / max_value))

def exploitation_score(exploits):
    """
    exploits: list[ExploitRecord]
    """
    if not exploits:
        return 0.0

    # reliability is already 0–1
    reliability_avg = sum(e.reliability for e in exploits) / len(exploits)

    # module type boost
    exploit_modules = sum(1 for e in exploits if "modules/exploits" in e.url.lower())
    exploit_boost = normalize(exploit_modules, len(exploits))

    return (0.7 * reliability_avg) + (0.3 * exploit_boost)

def chatter_score(chatter_items):
    """
    chatter_items: list[RSSRecord]
    """
    return normalize(len(chatter_items), 20)

def vendor_score(vendor_items):
    """
    vendor_items: list[VendorRecord]
    """
    return normalize(len(vendor_items), 10)

def recency_score(records):
    """
    records: list[AnyRecordWithPublishedField]
    """
    if not records:
        return 0.0

    now = datetime.utcnow()
    recent = sum(1 for r in records if (now - r.published) < timedelta(days=14))

    return normalize(recent, len(records))

def compute_heat(exploits, chatter, vendor, all_records):
    return (
        0.35 * exploitation_score(exploits) +
        0.25 * chatter_score(chatter) +
        0.20 * vendor_score(vendor) +
        0.20 * recency_score(all_records)
    )
