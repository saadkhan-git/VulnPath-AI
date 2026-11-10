# VulnPath AI — Research & PAEF Experimental Suite

This directory contains research artifacts, dataset preprocessing pipelines, baseline reproductions, and ablation experiments for the **Path-Aware Evidence Fusion (PAEF)** model.

## 1. Research Questions

- **RQ1 — Detection:** Does fusing deep semantic embeddings (CodeBERT) with AST structural graphs and static rule signals improve vulnerability detection over any individual approach?
- **RQ2 — Localization:** Does graph-based program dependency context improve fine-grained statement-level localization and source-to-sink path reconstruction?
- **RQ3 — Generalization:** Does the hybrid model maintain detection accuracy across unseen repositories and chronologically later codebases?
- **RQ4 — Remediation:** Can evidence-grounded vulnerability paths guide accurate, regression-free automated code repairs?

## 2. Baseline Matrix (B0 - B7)

| Baseline | Technique | Role |
| :--- | :--- | :--- |
| **B0** | Majority Class Classifier | Sanity / chance baseline |
| **B1** | TF-IDF + Logistic Regression | Classical machine learning baseline |
| **B2** | Pretrained CodeBERT | Frozen transformer semantic encoder baseline |
| **B3** | Bandit | Python security AST baseline |
| **B4** | Semgrep | Syntax & rule-based taint analysis baseline |
| **B5** | CodeQL | Deep semantic query reference |
| **B6** | GNN / GraphSAGE | Program dependency graph baseline |
| **B7** | **PAEF (Ours)** | Proposed hybrid evidence fusion model |

## 3. Directory Structure

```text
research/
├── literature_review/     # Literature tracking matrix & paper analyses
├── datasets/              # PyCode-Vul & PrimeVul normalized splits
├── preprocessing/         # Deduplication, sanitization, tokenization
├── baselines/             # Implementation of baselines B0 through B6
├── experiments/           # Training and evaluation runbooks
├── ablations/             # Component drop ablation studies
└── results/               # Metrics, confusion matrices, PR curves
```
