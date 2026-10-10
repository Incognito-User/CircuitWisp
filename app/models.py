from abc import ABC, abstractmethod
from datetime import datetime
from pydantic import BaseModel


class Source(ABC):
    """Common contract for model-like objects that can be serialized."""

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict):
        """Construct an instance from a dictionary payload."""
        raise NotImplementedError

    @abstractmethod
    def to_dict(self):
        """Serialize the instance to a dictionary."""
        raise NotImplementedError


class ExploitRecord(Source, BaseModel):
    source: str
    cve_id: str
    title: str
    url: str
    published: datetime | None = None
    reliability: float | None = None

    @classmethod
    def from_dict(cls, data: dict):
        """Build an ExploitRecord from a dictionary, tolerating partial payloads."""
        payload = dict(data)

        # Normalize published timestamp
        if "published" in payload and payload["published"] is not None:
            if not isinstance(payload["published"], datetime):
                try:
                    payload["published"] = datetime.fromisoformat(payload["published"])
                except ValueError:
                    payload["published"] = None

        return cls(**payload)

    def to_dict(self):
        """
        Provides a consistent dictionary representation for service layer output.
        Compatible with Pydantic v2 (model_dump) and v1 (dict) while normalizing
        datetime values into ISO 8601 strings so downstream services get JSON-safe data.
        """
        try:
            data = self.model_dump(mode="python")  # Pydantic v2
        except AttributeError:
            data = self.dict()  # Pydantic v1 fallback

        # Normalize datetime → ISO 8601
        if isinstance(data.get("published"), datetime):
            data["published"] = data["published"].isoformat()

        return data
