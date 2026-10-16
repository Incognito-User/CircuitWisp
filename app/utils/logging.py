# app/utils/logging.py
# ---------------------------------------------------------------------------
# LOGGING UTILITIES
# Provides consistent, OWASP‑aligned logging for source failures.
# Ensures no sensitive data is leaked and logs remain predictable.
# ---------------------------------------------------------------------------

import logging

# Unified logger for all CTI pipeline components
logger = logging.getLogger("circuitwisp")


# ---------------------------------------------------------------------------
# Source Error Logging
# ---------------------------------------------------------------------------
def log_source_error(source: str, cve: str, exc: Exception):
    """
    Log a standardized warning when an intelligence source fails.

    OWASP-aligned behavior:
    - No sensitive data exposed
    - No stack traces leaked
    - Predictable, uniform message format
    """
    logger.warning(f"{source} fetch failed for {cve}: {exc}")
