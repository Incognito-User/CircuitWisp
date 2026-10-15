<p align="center">

  <!-- Project Identity -->
  <img src="https://img.shields.io/badge/CircuitWisp-Setup_Guide-6f42c1.svg" />
  <img src="https://img.shields.io/badge/Version-1.0-blue.svg" />
  <img src="https://img.shields.io/badge/Status-Active-success.svg" />

  <!-- OS Badges -->
  <img src="https://img.shields.io/badge/Linux-🐧-yellow.svg" />
  <img src="https://img.shields.io/badge/macOS-🐧-lightgrey.svg" />
  <img src="https://img.shields.io/badge/Windows-🪟-blue.svg" />

  <!-- Runtime -->
  <img src="https://img.shields.io/badge/Python-3.11-blue.svg" />
  <img src="https://img.shields.io/badge/FastAPI-Backend-teal.svg" />

  <!-- Security -->
  <img src="https://img.shields.io/badge/OWASP-Compliant-blueviolet.svg" />
  <img src="https://img.shields.io/badge/Secrets-Host_Env_Required-red.svg" />

</p>

<br>

# ⚙️ CircuitWisp Setup Guide

This guide provides a complete setup workflow for installing, configuring, running, and extending CircuitWisp.  
It is designed for developers, analysts, and contributors who want to deploy CircuitWisp locally or integrate it into their CTI pipelines.

---

# 1. 📁 Repository Structure Overview

CircuitWisp is organized into two major layers:

- **sources/** — external intelligence ingestion  
- **utils/** — application logic, scoring, orchestration, endpoints  
- **easm.py (coming soon)** — external attack surface 

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
│  │   ├─ trending.py              # Trending module
│  │   ├─ actors.py                # Actor mapping
│  │   ├─ search.py                # Static search index
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

# 2. 🧰 Prerequisites

Before installing CircuitWisp, ensure you have:

### ✔ Python 3.11  
### ✔ pip  
### ✔ Git  
### ✔ (Optional) Docker  
### ✔ (Optional) API keys for enhanced intelligence

---

# 3. 📦 Installation

Clone the repository:

```bash
git clone https://github.com/Incognito-User/CircuitWisp.git
cd CircuitWisp
```

Install dependencies:
```bash
pip install -r requirements.txt
```

# 4. 🔐 Environment Setup

CircuitWisp supports two modes of secret management:

## ✔ Local Development (safe)
Use `.env` for convenience:

```bash
cp .env.example .env
```

Add your API keys:
```
NVD_API_KEY=
SHODAN_API_KEY=
GITHUB_TOKEN=
GREYNOISE_API_KEY=
```

## ✔ Production (OWASP Top 10 compliant)
> [!WARNING]
> 🚫 **Do not use `.env` in production — set secrets using host environment variables.**

## 🐧Linux / macOS
```bash
export NVD_API_KEY=xxxx
export SHODAN_API_KEY=xxxx
export GITHUB_TOKEN=xxxx
export GREYNOISE_API_KEY=xxxx
```

## 🪟 Windows (PowerShell)
```PowerShell
setx NVD_API_KEY "xxxx"
setx SHODAN_API_KEY "xxxx"
setx GITHUB_TOKEN "xxxx"
setx GREYNOISE_API_KEY "xxxx"
```

## 🐳 Docker
```bash
docker run \
  -e NVD_API_KEY=xxxx \
  -e SHODAN_API_KEY=xxxx \
  -e GITHUB_TOKEN=xxxx \
  -e GREYNOISE_API_KEY=xxxx \
  circuitwisp
```

## ☸️ Kubernetes
```Yaml
env:
  - name: NVD_API_KEY
    valueFrom:
      secretKeyRef:
        name: circuitwisp-secrets
        key: nvd
  - name: SHODAN_API_KEY
    valueFrom:
      secretKeyRef:
        name: circuitwisp-secrets
        key: shodan
  - name: GITHUB_TOKEN
    valueFrom:
      secretKeyRef:
        name: circuitwisp-secrets
        key: github
  - name: GREYNOISE_API_KEY
    valueFrom:
      secretKeyRef:
        name: circuitwisp-secrets
        key: greynoise
```

CircuitWisp loads secrets using:
```Python
os.getenv("NVD_API_KEY")
```
