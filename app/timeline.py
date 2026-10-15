# app/timeline.py
# ---------------------------------------------------------------------------
# TIMELINE ENGINE — Chronological CVE intelligence
# Delegates to snapshot engine to build discovery → exploit → KEV → advisory timeline.
# ---------------------------------------------------------------------------

from app.service import build_timeline as _build_timeline
from app.utils.logging import log_source_error


# ---------------------------------------------------------------------------
# Public Timeline Interface
# ---------------------------------------------------------------------------
async def build_timeline(cve_id: str):
    """
    Return chronological intelligence for a CVE.
    Safe fallback: returns empty list on failure.
    """
    try:
        return await _build_timeline(cve_id)
    except Exception as exc:
        log_source_error("timeline", cve_id, exc)
        return []
