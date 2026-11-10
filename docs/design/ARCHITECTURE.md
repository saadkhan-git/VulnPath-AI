# VulnPath AI — Implemented Architecture

## 1. Runtime flow

VulnPath AI is a local-first Python static analysis workbench. Its implemented scan flow is:

```text
Python file / safe ZIP extraction / bundled samples
                      |
           bounded target discovery
                      |
        Python standard-library AST parsing
                      |
      native AST detectors + custom YAML rules
             + optional Bandit adapter
                      |
          deduplication and risk summary
                      |
        local SQLite scan and findings store
                      |
          FastAPI API + React workbench
                      |
          SARIF / JSON / Markdown export
```

The scan target is parsed as text; the scanned source is never executed. ZIP extraction, file sizes, and target counts are bounded by application configuration.

## 2. Implemented analysis

The built-in detectors cover SQL injection (CWE-89), OS command injection (CWE-78), path traversal (CWE-22), hardcoded credentials (CWE-798), unsafe deserialization (CWE-502), and weak cryptography (CWE-327). Additional patterns can be loaded from YAML. Bandit is optional and is only invoked when enabled and installed.

Findings store a severity, detector confidence, source/sink descriptions when available, evidence notes, code context, and any detector-provided data-flow steps. The security score is a deterministic severity-weighted summary; it is not a CVSS score or model prediction.

## 3. API and workbench

The FastAPI application exposes health metadata, scan creation from file/ZIP/sample targets, scan status and findings, cancellation, deletion, workspace-wide findings, and report export. The React dashboard consumes these same response models and provides:

- overview metrics and recent scan status;
- Python file, ZIP, and sample scan creation;
- active progress polling and cooperative cancellation;
- finding filtering, code context, and evidence path display;
- local scan-history deletion; and
- SARIF 2.1.0, JSON, and Markdown downloads.

The browser frontend uses the Vite `/api` proxy in development. Run the backend on `127.0.0.1:8765` and frontend on `127.0.0.1:5173`.

## 4. Persistence

SQLite is stored locally at `.vulnpath/vulnpath.db` unless `VULNPATH_DATA_DIR` overrides the data directory. The schema contains:

- `scans`: scan identity, target, status, progress, timestamps, summary, and error state;
- `findings`: severity, source location, evidence, optional code flow, and review status; and
- `projects`: reserved schema for future project management (no project CRUD API is currently exposed).

## 5. Boundaries and future research

The shipped implementation does not include CodeBERT embeddings, a NetworkX program-dependency graph pipeline, trained Path-Aware Evidence Fusion (PAEF), automatic remediation/diff verification, or non-Python language parsers. These must not be presented as active analysis capabilities until implemented and independently validated. Current heuristic results can contain false positives and require analyst review.
