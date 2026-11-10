# ADR-001: Clean-Room Independent Architecture & Governance

## Status
Accepted

## Date
2026-11-10

## Context
The project owner (Mohammad Saad Khan) requires **VulnPath AI** to be built as a proprietary, research-grounded, production-quality SAST platform with 100% clean-room intellectual property provenance. Earlier iterations or exploratory forks that carried upstream third-party copyright notices must not be copied or incorporated. All rights, ownership, and copyright must reside solely with Mohammad Saad Khan.

Furthermore, development must proceed strictly phase-by-phase, ensuring credit efficiency, robust automated testing, and adherence to the *VulnPath AI Product Architecture & Research Development Plan*.

## Decisions

1. **Clean-Room Baseline:**
   All application logic, AST visitors, taint models, database access, API routes, and UI components are authored from scratch without copying reference code from third-party repositories.
2. **Local-First Security Model:**
   The backend runs on loopback `127.0.0.1`, avoiding public exposure. Code under analysis is strictly treated as untrusted data: it is never executed, and archive extraction incorporates strict path-normalization, file-count caps, and size limits.
3. **Decoupled Three-Branch Architecture:**
   The core engine will support three distinct evidence sources:
   - Branch A: Native AST structural detection.
   - Branch B: CodeBERT semantic embeddings.
   - Branch C: NetworkX program dependency graphs.
   These branches converge into the Path-Aware Evidence Fusion (PAEF) intelligence layer.
4. **Permissive Dependencies Only:**
   Only libraries with clear, permissive licenses (MIT, Apache-2.0, BSD-3-Clause, ISC) are approved. All licenses are tracked in `THIRD_PARTY_NOTICES`.
5. **Phase-by-Phase Verification:**
   Each phase must be accompanied by unit tests, documentation updates, and explicit user review before advancing.

## Consequences
- Independent code authorship ensures clean IP ownership for Mohammad Saad Khan.
- High test coverage and strict type annotations (Pydantic v2 + TypeScript) prevent regressions.
- Development remains disciplined and token-efficient.
