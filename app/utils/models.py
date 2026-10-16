# app/models.py
# ---------------------------------------------------------------------------
# DATA MODELS
# Provides structured, JSON‑safe representations of exploit intelligence
# records used throughout the CTI pipeline.
#
# OWASP‑aligned transparency:
# - Clear serialization contract
# - Safe datetime normalization
# - Predictable model behavior
# ---------------------------------------------------------------------------

from abc import ABC, abstractmethod
from datetime import datetime
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Abstract Source Contract
# ---------------------------------------------------------------------------
class Source(ABC):
    """
    Common contract for model-like objects that can be serialized.

    All intelligence record types must implement:
    - from_dict(): safe construction from raw payloads
    - to_dict(): JSON‑safe serialization for downstream services
    """

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict):
        """Construct an instance from a dictionary payload."""
        raise NotImplementedError

    @abstractmethod
    def to_dict(self):
        """Serialize the instance to a dictionary."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# ExploitRecord Model
# ---------------------------------------------------------------------------
class ExploitRecord(Source, BaseModel):
    """
    Unified exploit intelligence record.

    Fields:
    - source: origin of the intelligence (exploitdb, github, metasploit, vendor, rss)
    - cve_id: associated CVE identifier
    - title: human-readable title
    - url: reference URL
    - published: datetime of publication (ISO-normalized)
    - reliability: heuristic confidence score (0.0–1.0)
    """

    source: str
    cve_id: str
    title: str
    url: str
    published: datetime | None = None
    reliability: float | None = None

    # -----------------------------------------------------------------------
    # Safe Construction from Dict
    # -----------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict):
        """
        Build an ExploitRecord from a dictionary, tolerating partial payloads.
        Normalizes datetime fields into Python datetime objects.
        """

        payload = dict(data)

        # Normalize published timestamp
        if "published" in payload and payload["published"] is not None:
            if not isinstance(payload["published"], datetime):
                try:
                    payload["published"] = datetime.fromisoformat(payload["published"])
                except ValueError:
                    payload["published"] = None

        return cls(**payload)

    # -----------------------------------------------------------------------
    # JSON‑Safe Serialization
    # -----------------------------------------------------------------------
    def to_dict(self):
        """
        Provides a consistent dictionary representation for service layer output.
        Compatible with Pydantic v2 (model_dump) and v1 (dict).
        Ensures datetime values are ISO 8601 strings for JSON safety.
        """

        try:
            data = self.model_dump(mode="python")  # Pydantic v2
        except AttributeError:
            data = self.dict()  # Pydantic v1 fallback

        # Normalize datetime → ISO 8601
        if isinstance(data.get("published"), datetime):
            data["published"] = data["published"].isoformat()

        return data
