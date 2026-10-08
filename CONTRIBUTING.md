# Contributing to CircuitWisp

Thank you for your interest in contributing to CircuitWisp. This project is built with a focus on secure, modular, and maintainable development practices suitable for CTI and vulnerability intelligence workflows. The guidelines below help ensure consistency and quality across all contributions.

---

## 🧭 Guiding Principles

- **Security-first design** — safe defaults, strict validation, no secret leakage  
- **Modularity** — each exploit source is a self-contained module  
- **Clarity** — deterministic logic, explicit data models, predictable behavior  
- **Consistency** — uniform coding style, structured commits, clean architecture  

---

## 📁 Project Structure

CircuitWisp follows a modular Python layout:
```
CircuitWisp/
├─ app/
│  ├─ config.py
│  ├─ models.py
│  ├─ scoring.py
│  ├─ service.py
│  ├─ sources/
│  │   ├─ exploitdb.py
│  │   ├─ github.py
│  └─ api.py
├─ tests/
├─ .env.example
├─ .gitignore
├─ LICENSE
├─ README.md
└─ SECURITY.md
```

All new modules should follow this structure.

---

## 🔧 Development Setup

1. Clone the repository:
 ```bash
 git clone https://github.com/Incognito-User/CircuitWisp.git
 cd CircuitWisp
 ```
3. Install Dependencies**
```bash
pip install -r requirements.txt
```
3. Create your local environment file:
```bash
cp .env.example .env
```
4. Add your API keys and configuration table:

---

## 🧪 Running Tests
All new features must include tests. Run the test suite with:
```bash
pytest
```

If adding a new exploit source, include:
- unit tests for API client behavior.
- validation tests for Pydantic models.
- scoring/correlation tests if applicable.

---

## 🧱 Coding Standards
**Python Style**
- Use **PEP8** conventions
- Use **type hints** everwhere
- Use **Pydantic models** for all external data
- Avoid implicit behavior, be explicit and deterministic
- Prefer pure functions where possible

**Imports**
- Standard library
- Third-party
- Local modules

Example:
```python
import asyncio
import logging

import httpx
from pydantic import BaseModel

from app.models import ExploitRecord
```
**Logging**
Use structured logging:
```python
logger.info("Fetched exploit", source="exploitdb", cve=cve_id)
```

---

## 🌐 Adding a New Exploit Source
All exploit-source modules must:
1. Live in `app/sources`
2. Expose a single async function:
   ```python
   async def fetch_exploits(cve_id: str) -> list[ExploitRecord]:
   ```
3. Use safe HTTP client patterns (`httpx.AsyncClient`)
4. Validate all external data with Pydantic models
5. Return normalized `ExploitRecord` objects
6. Include tests in `tests/`

---

## 🔀 Branching Strategy
- `main` - stable, production-ready
- `dev` - active development
- Feature branches:
  ```feature/<short-description.```
  Example:
  ```feature/github-source-module```

  ---

## 📝 Commit Message Format
Use clear, structured commit messages:
```
feat: add GitHub exploit-source module
fix: correct scoring logic for multi-source correlation
docs: update README with installation steps
test: add unit tests for exploitdb client
refactor: simplify config loader
```

---

## 📬 Pull Requests
Before submitting a PR:
- Ensure tests pass
- Ensure linting passes
- Update documentation if needed
- Reference related issues
- Keep PRs focused, one feature or fix per PR

PRs should include:
- Summary of changes
- Rationale
- Testing notes
- Any known limitations

---

## 🤝 Code of Conduct
By contributing, you agree to uphold respectful and professional communication. (See `CODE_OF_CONDUCT.md` if present.)

---

## 🙏 Thank You
Your contributions help strengthen `CircuitWisp` and the CTI community it supports. We appreciate your time, expertise, and commitment to secure development.
