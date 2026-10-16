# app/techstack.py

import json
from pathlib import Path
from typing import List

TECH_STACK_PATH = Path("config/tech_stack.json")


def load_tech_stack() -> List[str]:
    if not TECH_STACK_PATH.exists():
        return []
    try:
        data = json.loads(TECH_STACK_PATH.read_text())
        return data.get("products", []) or []
    except Exception:
        return []
