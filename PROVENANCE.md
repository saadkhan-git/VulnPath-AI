# VulnPath AI — Provenance & Clean-Room Governance Record

**Product Name:** VulnPath AI  
**Tagline:** "Trace the path. Fix the flaw."  
**Creator & Sole Copyright Holder:** Mohammad Saad Khan  
**GitHub Profile:** [https://github.com/saadkhan-git](https://github.com/saadkhan-git)  
**Governance Date:** November 2026  
**Status:** Clean-Room Independent Development  

---

## 1. Clean-Room Authorship Statement

VulnPath AI is designed and implemented as an original, clean-room static application security testing (SAST) and vulnerability intelligence platform.

All source code, architectural components, detection heuristics, AST visitors, taint models, risk scoring algorithms, database schemas, API contracts, dashboard user interfaces, and test fixtures are authored independently by **Mohammad Saad Khan** with agentic pair-programming assistance from Antigravity.

### Clean-Room Verification Principles:
- **No Direct Code Copying:** No source code, scanner rules, test fixtures, or UI assets have been copied, adapted, decompiled, or ported from any third-party repository or earlier forked derivatives.
- **Specification-Driven:** Implementation strictly follows functional and architectural specifications:
  1. *VulnPath AI Implementation Specification*
  2. *VulnPath AI Product Architecture & Research Development Plan* (14-page research blueprint detailing the Path-Aware Evidence Fusion [PAEF] model)
- **Public Standards Compliance:** All security vulnerability definitions, severity classifications, and export schemas adhere to official public standards:
  - Common Weakness Enumeration (CWE) via MITRE
  - OWASP Top 10 (2021 / 2025 drafts)
  - OASIS SARIF v2.1.0 (Static Analysis Results Interchange Format)
  - Official Python `ast` Standard Library Documentation

---

## 2. Module Provenance Registry

| Module Path | Primary Responsibility | Authorship / Origin | Standards / Reference |
| :--- | :--- | :--- | :--- |
| `backend/app/core/` | System configuration, security bounds, loopback isolation | Mohammad Saad Khan | OWASP Local API security guidelines |
| `backend/app/schemas/` | Pydantic v2 domain schemas (Finding, Scan, Project) | Mohammad Saad Khan | SARIF 2.1.0 & VulnPath Finding Schema |
| `backend/app/database/` | SQLite schema, migration, and async query store | Mohammad Saad Khan | SQLite3 & standard asynchronous DB patterns |
| `backend/app/api/` | FastAPI REST endpoints & scan orchestration | Mohammad Saad Khan | RESTful API standards |
| `backend/app/ingestion/` | Safe archive extractor, ZIP slip prevention, quota checks | Mohammad Saad Khan | CWE-22 & CWE-400 mitigation best practices |
| `backend/app/parsing/` | Python AST extractor & structural node mapper | Mohammad Saad Khan | Python `ast` specification (PEP 339) |
| `backend/app/analysis/` | AST detectors (CWE-89, 78, 22, 798, 502, 327), engine & scoring | Mohammad Saad Khan | Independent AST pattern matching & taint tracking |
| `backend/app/intelligence/`| Severity, reachability, confidence, and PAEF logic | Mohammad Saad Khan | VulnPath Research Architecture (PAEF v1–v4) |
| `frontend/src/` | Security analyst dashboard, React Flow graph view | Mohammad Saad Khan | Original dark cybersecurity workbench design |

---

## 3. AI Assistance Disclosure

In accordance with academic and professional transparency guidelines, AI assistance was utilized exclusively as an interactive pair programmer for:
1. Generating initial boilerplate code under the author's direction and requirements.
2. Formulating unit test cases and boundary condition assertions.
3. Formatting documentation and SPDX compliance notices.

At no point was any copyrighted proprietary code from external closed-source or unverified repositories retrieved or injected into this codebase.

---

## 4. Third-Party Open Source Compliance

All external dependencies utilized in this project are strictly limited to well-established, permissively licensed open-source libraries (e.g., MIT, BSD-3-Clause, Apache-2.0, ISC). Complete license texts and attribution notices are maintained in `THIRD_PARTY_NOTICES`.
