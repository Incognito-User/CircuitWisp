import re

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def validate_cve(cve_id: str) -> bool:
    return bool(CVE_PATTERN.match(cve_id))