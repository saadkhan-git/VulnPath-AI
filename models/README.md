# VulnPath AI — Model Registry & Checkpoints

This directory stores configuration files, model cards, and weights for learned components in VulnPath AI.

## Structure

```text
models/
├── checkpoints/       # Trained model weights (Git ignored)
├── configs/           # Model hyperparameters and feature extraction configs
└── model_cards/       # Model provenance, training data hashes, and metrics
```

## Model Card Specifications

Every model deployed in VulnPath AI must feature a model card adhering to reproducible ML standards:
- Architecture & backbone (e.g., `microsoft/codebert-base`, XGBoost 2.0+)
- Training datasets and exact split hashes
- Precision, Recall, F1, PR-AUC, and Matthews Correlation Coefficient (MCC)
- Limitations, known biases, and failure modes
