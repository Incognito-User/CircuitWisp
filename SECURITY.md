# Security Policy

CircuitWisp is a security-focused project, and we take responsible disclosure seriously. This document outlines how to report vulnerabilities, what information to include, and how we handle security-related communications.

---

## Reporting a Vulnerability

If you discover a security issue within CircuitWisp, please report it responsibly.

**Preferred contact:**  
<PreferUnknown@proton.me>

When reporting, please include:

- A clear description of the issue  
- Steps to reproduce the vulnerability  
- Any relevant logs or output  
- Potential impact or severity (if known)

Please **do not** open public GitHub issues for sensitive vulnerabilities.  
Direct, private communication ensures responsible handling and protects users.

---

## Scope

This security policy applies to:

- CircuitWisp’s codebase  
- Exploit-source integrations  
- Scoring, correlation, and monitoring logic  
- Any future API or dashboard components  

It does **not** apply to:

- External CVEs or vulnerabilities unrelated to CircuitWisp  
- Issues within third-party libraries or APIs  
- Misconfigurations in user environments  

---

## Supported Versions

Security updates will be applied to the latest active development branch.  
Older versions may not receive patches unless the issue is critical.

---

## Responsible Disclosure Expectations

We ask that you:

- Give us reasonable time to investigate and address the issue  
- Avoid publicly sharing exploit details until a fix is released  
- Provide clear, reproducible information whenever possible  

We commit to:

- Acknowledging your report promptly  
- Investigating the issue thoroughly  
- Communicating timelines and fixes transparently  
- Crediting responsible disclosures when appropriate  

---

## Security Best Practices for Users

To keep your CircuitWisp deployment secure:

- Never commit `.env` files or secrets  
- Rotate API keys regularly  
- Use least-privilege tokens for exploit-source integrations  
- Keep dependencies updated  
- Run CircuitWisp in isolated environments when possible  

---

## Thank You

We appreciate your help in keeping CircuitWisp secure.  
Every responsible report strengthens the project and the community it supports.
