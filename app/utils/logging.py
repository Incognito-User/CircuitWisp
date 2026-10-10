# app/utils/logging.py
import logging

logger = logging.getLogger("circuitwisp")

def log_source_error(source: str, cve: str, exc: Exception):
    logger.warning(f"{source} fetch failed for {cve}: {exc}")
