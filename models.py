from pydantic import BaseModel
from datetime import datetime

class ExploitRecord(BaseModel):
    source: str
    cve_id: str
    title: str
    url: str
    published: datetime
    reliability: float | None = None
