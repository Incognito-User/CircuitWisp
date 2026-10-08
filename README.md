# 🌙 CircuitWisp

CircuitWisp is a secure, modular exploit‑activity monitoring engine built for modern CTI and vulnerability intelligence workflows. It tracks PoCs and exploit signals across multiple sources using an OWASP‑aligned Python architecture — a small “wisp in the wires” watching the threat landscape.

---

## ✨ Features

- Async monitoring of exploit sources (ExploitDB, GitHub, more coming)
- Strict input validation using Pydantic models
- Secure external API clients with safe request handling
- Deterministic exploit scoring and correlation logic
- Dashboard‑ready JSON output for analyst and management views
- Modular structure designed for future CTI/VM expansion

---

## 📦 Installation

```bash
git clone https://github.com/Incognito-User/CircuitWisp.git
cd CircuitWisp
pip install -r requirements.txt
```

## 🔐 Environment Setup
Copy the example environment file:
```bash
cp .env.example .env
```
Then add your API keys and configuration vlaues.

##  🚀 Usage Example
```python
import asyncio
from app.service import monitor_exploitation

results = asyncio.run(monitor_exploitation(["CVE-2024-12345"]))
print(results)
```
## 🧩 Project Structure
```
circuitwisp/
├─ app/
│  ├─ config.py          # Secure config + secrets loading
│  ├─ models.py          # Input validation + schemas
│  ├─ scoring.py         # Exploit scoring logic
│  ├─ service.py         # Orchestrator
│  ├─ sources/           # External exploit-source clients
│  │   ├─ exploitdb.py
│  │   ├─ github.py
│  └─ api.py             # (future) FastAPI dashboard API
├─ tests/
├─ .env.example
├─ .gitignore
└─ README.md
```

## 📅 Roadmap
- Add Metasploit + vendor advisory integrations
- Add Asset Context Vault (sanitized exposure flags)
- Add FastAPI dashboard API
- Add Analyst + Management dashboards
- Add SaaS workflow abuse detection module
- Add Docker deployment + CI/CD

## ⚖️ License

CircuitWisp is released under the **MIT License**, a simple and permissive open‑source license that allows others to use, modify, and distribute the project with proper attribution. This keeps the project accessible for researchers, defenders, and CTI teams while maintaining flexibility for future development and integration.

## 🌌 About the Name
CircuitWisp blends cyberpunk circuitry with Ghibli‑style spirit imagery — a tiny digital wisp quietly watching the grid for emerging threats.
