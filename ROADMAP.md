# CircuitWisp Roadmap

This roadmap outlines the planned development phases for CircuitWisp — a modular, secure exploit‑activity monitoring engine designed for CTI and vulnerability intelligence workflows. Items are grouped by development horizon and may shift as the project evolves.

---

## 🚀 Near-Term (Active Development)

### **Core Monitoring Engine**
- Implement ExploitDB monitoring module  
- Implement GitHub exploit‑chatter monitoring module  
- Add deterministic exploit scoring logic  
- Add correlation logic for multi‑source exploit signals  

### **Architecture & Security**
- Finalize Pydantic models for input validation  
- Harden external API client request handling  
- Add structured logging with severity levels  
- Add configuration loader (`config.py`) with safe defaults  

### **Developer Experience**
- Add initial test suite (`tests/`)  
- Add FastAPI scaffolding for future dashboard API  
- Add CI workflow for linting + tests  

---

## 🌙 Mid-Term (Feature Expansion)

### **Source Integrations**
- Add Metasploit module  
- Add vendor advisory ingestion (Cisco, Microsoft, etc.)  
- Add RSS/Atom feed ingestion for exploit chatter  
- Add Twitter/X monitoring (if API access is viable)  

### **Contextual Intelligence**
- Add Asset Context Vault (sanitized exposure flags)  
- Add CVSS + EPSS enrichment  
- Add exploit reliability scoring  

### **Dashboards**
- Analyst dashboard (JSON → UI)  
- Management dashboard (summaries, trends, exposure flags)  
- Add API authentication layer  

---

## 🔮 Long-Term (Platform Vision)

### **Advanced Intelligence**
- ML-assisted exploit clustering  
- Behavioral exploit trend detection  
- Threat actor correlation (optional module)  

### **Deployment & Scale**
- Full Docker deployment  
- Kubernetes-ready manifests  
- Horizontal scaling for high-volume monitoring  

### **Ecosystem**
- Plugin system for custom exploit sources  
- Public API for external CTI tools  
- Optional SaaS workflow abuse detection module  

---

## 🧭 Guiding Principles

- **Security-first design** — safe defaults, strict validation, no secret leakage  
- **Modularity** — every exploit source is a self-contained module  
- **Transparency** — deterministic scoring and clear logic paths  
- **Scalability** — designed for both personal use and enterprise CTI teams  
- **Aesthetic identity** — cyberpunk circuitry meets Ghibli‑style spirit imagery  

---

## 📌 Notes

This roadmap is a living document and will evolve as CircuitWisp grows.  
Major changes will be reflected here and in the project’s milestones.

