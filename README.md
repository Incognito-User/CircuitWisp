<p align="center">
  <img src="assets/logo/CircuitWisp-Logo.png" alt="CircuitWisp Logo" width="300">
</p>

<h1 align="center">🌙 CircuitWisp</h1>

<p align="center"><i>A quiet little wisp in the wires watching the threat landscape.</i></p>

## 🌙 Description
CircuitWisp is a secure, modular cyber‑threat intelligence engine designed for modern CTI, vulnerability management, and exploitation‑signal monitoring workflows. It aggregates intelligence from multiple sources, builds structured CVE snapshots, computes deterministic heat scores, and exposes a clean FastAPI interface for analysts, automation pipelines, and dashboards.

CircuitWisp is built to be small, fast, and extensible — a quiet little wisp in the wires watching the threat landscape.

---

<!-- Project Identity -->
![CircuitWisp](https://img.shields.io/badge/CircuitWisp-🌙_CyberGhibli-6f42c1.svg)

<!-- Core Metadata -->
![Python](https://img.shields.io/badge/Python-3.11-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

<!-- Private Repo Indicators -->
![Last Commit](https://img.shields.io/badge/Last_Commit-Private_Repo-lightgrey.svg)
![Issues](https://img.shields.io/badge/Issues-Private_Repo-lightgrey.svg)

<!-- Intelligence Integrations -->
![EPSS](https://img.shields.io/badge/EPSS-Integrated-orange.svg)
![KEV](https://img.shields.io/badge/KEV-Integrated-red.svg)
![Exploit Sources](https://img.shields.io/badge/ExploitDB%20%2B%20Metasploit-Enabled-purple.svg)

<!-- Architecture -->
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-teal.svg)
![OWASP](https://img.shields.io/badge/OWASP-Aligned-blueviolet.svg)

---

## ✨ Features
- **FastAPI‑powered CTI endpoints**  
`/cve`, `/timeline`, `/scorebreakdown`, `/trending`, `/actors`, `/search`, `/health/sources`, `/config`

- **Deterministic exploit‑activity scoring**  
EPSS, KEV, exploit metadata, and reliability weighting

- **Modular intelligence ingestion**  
ExploitDB, Metasploit, GitHub PoCs, KEV, EPSS, NVD (more coming)

- **Structured CVE snapshots**  
Unified JSON output for dashboards, SIEM enrichment, and analyst workflows

- **Static intelligence modules (Phase 1)**  
Trending, Actors, Search — validated and ready for dynamic expansion

- **OWASP‑aligned architecture**  
Safe request handling, strict Pydantic validation, and clean separation of concerns

- **Future‑ready design**  
Built for expansion into dynamic intel feeds, asset context, and SaaS abuse detection

---

## 📦 Installation
```Bash
git clone https://github.com/Incognito-User/CircuitWisp.git
cd CircuitWisp
pip install -r requirements.txt
```

---

## 🔐 Environment Setup
Copy the example environment file:
```Bash
cp .env.example .env
```
Then add your API keys and configuration values.

---

## 🚀 Usage Example
```python
import asyncio
from app.service import monitor_exploitation

results = asyncio.run(monitor_exploitation(["CVE-2024-12345"]))
print(results)
```

---

## 🧩 Project Structure
```
CircuitWisp/
├─ app/
│  ├─ api.py              # FastAPI router + endpoint definitions
│  ├─ config.py           # Secure config + secrets loading
│  ├─ models.py           # Pydantic schemas
│  ├─ scoring.py          # Heat score + risk logic
│  ├─ service.py          # Snapshot + timeline orchestrator
│  ├─ health.py           # Source availability checks
│  ├─ scorebreakdown.py   # Transparent scoring explanation
│  ├─ trending.py         # Static trending module (Phase 1)
│  ├─ actors.py           # Static actor mapping (Phase 1)
│  ├─ search.py           # Static search index (Phase 1)
│  ├─ sources/            # External intel clients
│  │   ├─ exploitdb.py
│  │   ├─ metasploit.py
│  │   ├─ github.py
│  │   └─ ...
├─ docs/
│  └─ validation/
│      └─ Phase1_Endpoint_Validation/   # Screenshot validation artifacts
├─ tests/
├─ .env.example
├─ .gitignore
└─ README.md
```

---

## 📅 Roadmap
**Phase 2 — Dynamic Intelligence**
- Dynamic Trending (EPSS deltas, KEV changes, exploit activity)
- Dynamic Actor Enrichment (ATT&CK, campaigns, tooling)
- Dynamic Search (KEV, NVD, EPSS, vendor advisories, exploit metadata)

**Phase 3 — Dashboard + Context**
- FastAPI dashboard API
- Analyst + management dashboards
- Asset Context Vault (sanitized exposure flags)
- SaaS workflow abuse detection module

**Phase 4 — Deployment**
- Docker deployment
- CI/CD pipeline
- Production hardening

---

## ⚖️ License
CircuitWisp is released under the MIT License, a simple and permissive open‑source license that allows others to use, modify, and distribute the project with proper attribution. This keeps the project accessible for researchers, defenders, and CTI teams while maintaining flexibility for future development and integration.

---

## 🌌 About the Name
CircuitWisp blends cyberpunk circuitry with Ghibli‑style spirit imagery — a tiny digital wisp quietly watching the grid for emerging threats.
