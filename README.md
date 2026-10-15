<p align="center">
  <img src="assets/logo/CircuitWisp-Logo.png" alt="CircuitWisp Logo" width="300">
</p>

<h1 align="center">🌙 CircuitWisp</h1>

<p align="center"><i>A quiet little wisp in the wires watching the threat landscape.</i></p>

---

# 🌙 Description

CircuitWisp began as a **small, modular cyber‑threat intelligence engine** designed to unify EPSS, KEV, NVD, and exploit metadata into clean, structured CVE snapshots.

It has since evolved into a **full-spectrum CTI + Exposure Intelligence platform**, combining:

- **Global threat visibility** (EPSS, KEV, NVD, Shodan, GreyNoise, ExploitDB, Metasploit, GitHub PoCs, MITRE, vendor advisories)  
- **Internal relevance mapping** (tech stack, service context)  
- **Optional external attack surface awareness (EASM — in development)**  
- **Deterministic exploitation scoring (SREI)**  
- **Dashboard-ready JSON outputs** for analysts, SIEMs, and automation pipelines  

CircuitWisp is built to be small, fast, and extensible — a quiet little wisp in the wires watching the grid for emerging threats.

---

# 🛡️ Project Identity

![CircuitWisp](https://img.shields.io/badge/CircuitWisp-🌙_CyberGhibli-6f42c1.svg)
![Python](https://img.shields.io/badge/Python-3.11-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

![EPSS](https://img.shields.io/badge/EPSS-Integrated-orange.svg)
![KEV](https://img.shields.io/badge/KEV-Integrated-red.svg)
![Exploit Sources](https://img.shields.io/badge/ExploitDB%20%2B%20Metasploit-Enabled-purple.svg)

![FastAPI](https://img.shields.io/badge/FastAPI-Backend-teal.svg)
![OWASP](https://img.shields.io/badge/OWASP-Aligned-blueviolet.svg)

---

# ✨ Features

## 🔵 Global Threat Intelligence
CircuitWisp aggregates intelligence from multiple external sources:

- EPSS exploit probability  
- CISA KEV exploitation confirmation  
- NVD CVE metadata  
- ExploitDB + Metasploit exploit references  
- GitHub PoCs  
- GreyNoise scanning activity  
- Shodan global exposure intelligence  
- MITRE ATT&CK techniques + actor mapping  
- Vendor advisories (RSS + vendor feeds)  
- CISA advisories + campaign intelligence  

All signals are unified into structured CVE snapshots.

---

## 🔵 Deterministic Exploit‑Activity Scoring (SREI)
CircuitWisp computes a deterministic exploitation score using:

- EPSS probability  
- KEV status  
- exploit metadata  
- threat activity  
- global exposure  
- internal relevance (tech stack)  
- optional external exposure (EASM — in development)

This produces a transparent, explainable risk score.

---

## 🔵 Structured CVE Snapshots
Every CVE returns a unified JSON object containing:

- metadata  
- exploit references  
- EPSS  
- KEV  
- NVD  
- GreyNoise  
- Shodan  
- MITRE  
- vendor advisories  
- internal relevance  
- timeline  
- SREI score  
- score breakdown  

Perfect for dashboards, SIEM enrichment, and automation.

---

## 🔵 Modular Intelligence Ingestion
CircuitWisp includes clean, isolated modules for:

- EPSS  
- KEV  
- NVD  
- Shodan  
- GreyNoise  
- ExploitDB  
- Metasploit  
- GitHub  
- MITRE  
- CISA advisories  
- CISA campaigns  
- Vendor advisories  
- RSS feeds  

Each module is self-contained and easy to extend.

---

## 🔵 Optional External Attack Surface Awareness (EASM — In Development)
CircuitWisp is expanding into **environment‑specific external exposure intelligence**.

EASM is:

- **optional**  
- **runtime-loaded**  
- **OWASP-aligned**  
- **never baked into the image**  
- **never stored in the repo**  

Users may provide external asset inventories at runtime via:

- mounted files  
- environment variables  
- external ASM/EASM APIs  

CircuitWisp will detect whether *your* assets are externally exposed to a given CVE.

---

## 🔵 GreyNoise (No API Key Required — Lightweight Mode)

CircuitWisp integrates GreyNoise in a **keyless mode** to remain lightweight and OWASP‑aligned.

### Baseline (no key):
- Public tags  
- Public noise classifications  
- Public CVE scanning notes  
- Public actor fingerprints  
- High-level “noise vs targeted” context  

### With API key (future optional enhancement):
- IP reputation  
- Noise scores  
- GNQL queries  
- IP timelines  
- Behavioral fingerprints  
- CVE-specific scanning queries  

GreyNoise becomes a powerful exploitation signal when authenticated.

---

## 🔵 FastAPI‑Powered CTI Endpoints

- `/cve`  
- `/timeline`  
- `/scorebreakdown`  
- `/trending`  
- `/actors`  
- `/search`  
- `/health/sources`  
- `/config`

---

## 🔵 OWASP‑Aligned Architecture

- No sensitive data baked into the image  
- Strict Pydantic validation  
- Safe request handling  
- Clean separation of concerns  
- Runtime-only asset context (EASM)

---

# 🔐 API Key / Token Impact by Module

CircuitWisp operates securely without requiring API keys, but several modules provide richer intelligence when keys are supplied.

| Module        | Works Without Key | Improved With Key | Notes |
|---------------|------------------|-------------------|-------|
| EPSS          | ✔ Yes            | ❌ No             | Fully public |
| KEV           | ✔ Yes            | ❌ No             | Fully public |
| NVD           | ✔ Yes            | ✔ Yes            | Key improves rate limits |
| ExploitDB     | ✔ Yes            | ❌ No             | Fully public |
| Metasploit    | ✔ Yes            | ❌ No             | Fully public |
| GitHub PoCs   | ✔ Limited        | ✔ Full           | Token strongly recommended |
| GreyNoise     | ✔ Limited        | ✔ Full           | Key unlocks IP‑level intel |
| Shodan        | ❌ No            | ✔ Full           | Key required |
| MITRE         | ✔ Yes            | ❌ No             | Fully public |
| Vendor Feeds  | ✔ Yes            | ❌ No             | Fully public |
| EASM          | ✔ Partial        | ✔ Full           | Depends on Shodan key |

---

## 🧩 Project Structure

CircuitWisp is organized into two major layers:

- **sources/** — external intelligence ingestion  
- **utils/** — application logic, scoring, orchestration, endpoints  
- **easm.py (coming soon)** — external attack surface module

```
CircuitWisp/
├─ app/
│  ├─ sources/                     # External intelligence ingestion
│  │   ├─ cisa.py
│  │   ├─ cisa_campaigns.py
│  │   ├─ epss.py
│  │   ├─ exploitdb.py
│  │   ├─ github.py
│  │   ├─ greynoise.py
│  │   ├─ kev.py
│  │   ├─ metasploit.py
│  │   ├─ mitre.py
│  │   ├─ nvd.py
│  │   ├─ rss.py
│  │   ├─ shodan.py
│  │   └─ vendor.py
│  │
│  ├─ utils/                       # Application logic
│  │   ├─ api.py                   # FastAPI endpoints
│  │   ├─ service.py               # Orchestration layer
│  │   ├─ scoring.py               # Executes the SREI scoring engine
│  │   ├─ srei.py                  # Defines the SREI model + weighting logic
│  │   ├─ heat.py                  # Unified CVE snapshot builder
│  │   ├─ timeline.py              # Timeline builder
│  │   ├─ techstack.py             # Internal relevance mapping
│  │   ├─ trending.py              # Trending module (Phase 1)
│  │   ├─ actors.py                # Actor mapping (Phase 1)
│  │   ├─ search.py                # Static search index (Phase 1)
│  │   ├─ campaigns.py             # CISA campaign enrichment
│  │   ├─ models.py                # Pydantic models for CTI schemas
│  │   ├─ health.py                # Source health checks
│  │   ├─ config.py                # Runtime configuration + secrets
│  │   ├─ tools.py                 # Utility functions (EASM staging area)
│  │   ├─ validation.py            # Input validation
│  │   ├─ easm.py                  # ⭐ External Attack Surface Module (Phase 3)
│  │   └─ main.py                  # Application entrypoint
│
├─ data/
├─ tests/
├─ Dockerfile
├─ requirements.txt
├─ README.md
├─ ROADMAP.md
├─ SECURITY.md
├─ CONTRIBUTING.md
└─ CODE_OF_CONDUCT.md
```

---

# 🧠 Module Purpose & Reasoning

CircuitWisp is intentionally modular. Each component exists for a specific reason and solves a distinct part of the CTI + Exposure Intelligence workflow.

### 🔹 sources/ — External Intelligence Ingestion
Fetches, normalizes, and returns raw intelligence from external providers.

### 🔹 utils/ — Application Logic
Orchestrates intelligence, builds snapshots, computes scores, and exposes endpoints.

### 🔹 EASM Module (_Coming Soon_)
Will live in: `app/utils/easm.py`

Provides:

- runtime-loaded asset inventory  
- external exposure detection  
- Shodan-assisted EASM checks  
- local exposure relevance for SREI scoring  
- dashboard integration (Phase 3)

---

# 📦 Installation

```bash
git clone https://github.com/Incognito-User/CircuitWisp.git
cd CircuitWisp
pip install -r requirements.txt
```

# 🔐 Environment Setup
Copy the example environment file: 
```bash
cp .env.example .env
```

Add your API keys:

- NVD
- EPSS
- KEV
- Shodan
- GitHub

### Optional: EASM (In Development)
CircuitWisp does not store any sensitive asset data. Users may optionally provide external asset inventories at runtime via:

- mounted files (e.g., /app/config/easm.json)
- environment variables (EASM_DOMAINS, EASM_IP_RANGES)
- external ASM/EASM APIs

**_These values are never persisted._**

# 🚀 Usage Example
```python
import asyncio
from app.utils.service import monitor_exploitation

results = asyncio.run(monitor_exploitation(["CVE-2024-12345"]))
print(results)
```

## 📅 Roadmap

For the full development roadmap, see:

➡️ [RoadMap.md](RoadMap.md)

# ⚖️ License
CircuitWisp is released under the MIT License — simple, permissive, and defender-friendly.

# 🌌 About the Name
CircuitWisp blends cyberpunk circuitry with Ghibli‑style spirit imagery — a tiny digital wisp quietly watching the grid for emerging threats.



