# FormatShield — Experiment Index

This file maps every experiment to its script, result CSV, and the paper table it supports.

| ID | Experiment Name | Script | Result CSV | Paper Section | Key Numbers |
|---|---|---|---|---|---|
| EXP-1 | LLM Compliance Study | `experiments/exp1_compliance_study.py` | `results/exp1_compliance_study.csv` | §7.1 / Motivation | 23.1% compliance; Llama-3.3 = 33.3% HIGH RISK |
| EXP-2 | Vulnerability Heatmap | `experiments/exp2_vulnerability_heatmap.py` | `results/exp2_heatmap.csv` | §7.1 / Threat Model | 2 HIGH-RISK; 4 ZERO-RISK |
| EXP-3 | RAG Pipeline End-to-End | `experiments/exp3_rag_pipeline.py` | `results/exp3_rag_pipeline.csv` | §7.2 / System Validation | 80% → 0% attack success |
| E1 | Main Benchmark | *(run via FormatShieldFinalV4.ipynb)* | *(inline in notebook)* | §7.3 Primary Result | F1=0.9750; Prec=1.000; FPR=0.000 |
| EX-A | 5-Fold Cross-Validation | `experiments/exp_exa_crossvalidation.py` | `results/exa_crossvalidation.csv` | §7.3 Generalisation | F1=0.9750 ± 0.0074; FPR=0.000 all folds |
| EX-B | Weight Grid Search | `experiments/exp_exb_weight_grid.py` | `results/exb_weight_grid.csv` | §5 System Design | WS=WC=0.40; WD=0.20 |
| EX-C | Threshold Sweep | `experiments/exp_exc_threshold_sweep.py` | `results/exc_threshold_sweep.csv` | §5 System Design | Q=0.25 Pareto-optimal |
| EX-D | Dual-Path Contribution | `experiments/exp_exd_dual_path.py` | `results/exd_dual_path_summary.csv` | §5.4 Ablation | Structural=85.4%; Semantic=4.6% |
| R3 | Real-World FPR | `experiments/exp_r3_realworld_fpr.py` | `results/r3_realworld_fpr.csv` | §7.4 FPR Safety | FPR=0.0000 on 350 professional docs |
| R4 | Novel OOD Attack | `experiments/exp_r4_novel_ood.py` | `results/r4_novel_ood.csv` | §7.4 Generalisation | F1=1.000 on 20 OOD attacks |
| R5/R6 | White-Box Adaptive Attack | `experiments/exp_r5r6_whitebox.py` | `results/r5r6_whitebox.csv` | §7.5 Robustness | 7/10 detected; 3 evasions documented |
| EXP-5 | Independent Blind Attacks | `experiments/exp_exp5_independent.py` | `results/exp5_independent_attacks.csv` | §7.5 Independent Validation | 14/20 recall; 0 benign FP |
| E_REAL | Real arXiv Papers | `experiments/exp_e_real_arxiv.py` | `results/e_real_arxiv_papers.csv` | §7.4 Real-World | 15/15 detected |
| E_REAL_B | Wikipedia FPR | `experiments/exp_e_real_arxiv.py` | `results/e_real_wikipedia_fpr.csv` | §7.4 Real-World | FPR=0.000 |
| E9a | External: deepset | `experiments/exp_e9_external_benchmark.py` | `results/e9_external_benchmark.csv` | §7.6 External | Prec=1.000; FPR=0.000 |
| E9b | External: neuralchemy | `experiments/exp_e9_external_benchmark.py` | `results/e9_external_benchmark.csv` | §7.6 External | Prec=1.000; FPR=0.000 |
| E11 | McNemar + Bootstrap | `experiments/exp_e11_statistical_tests.py` | `results/e11_mcnemar.csv` + `results/e11_bootstrap_ci.csv` + `results/e11_tier_breakdown.csv` | §7.7 Statistics | F1=0.9583; κ=0.924; all p≤0.0044 |

---

## How to Reproduce All Results

```bash
# Install dependencies
pip install -r requirements.txt

# Run all experiment scripts sequentially
python experiments/run_all.py

# Or run individual experiments
python experiments/exp1_compliance_study.py
python experiments/exp_exa_crossvalidation.py
python experiments/exp_e9_external_benchmark.py
python experiments/exp_e11_statistical_tests.py
```

> **Note:** EXP-1 and EXP-3 require API keys set in `.env` (see `.env.example`).  
> All other experiments are fully offline and deterministic.

---

## Result File Naming Convention

| Prefix | Meaning |
|---|---|
| `exp1_`, `exp2_`, `exp3_` | Original LLM study experiments |
| `exa_`, `exb_`, `exc_`, `exd_` | Ablation and parameter optimisation |
| `r3_`, `r4_`, `r5r6_` | Real-world validation experiments |
| `exp5_` | Independent blind attack set |
| `e_real_` | Real published paper detection |
| `e9_` | External HuggingFace benchmark |
| `e11_` | Statistical significance tests |
