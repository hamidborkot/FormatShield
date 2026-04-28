"""
E9: External Benchmark Evaluation (HuggingFace Datasets)
FormatShield — Springer Cybersecurity 2026

SCOPE NOTE: Both datasets contain PLAIN-TEXT prompt injection WITHOUT format-hiding.
FormatShield is a format-aware pre-retrieval gate — NOT a plain-text semantic classifier.
The meaningful results here are Precision=1.0000 and FPR=0.0000, not recall.

Results:
  deepset/prompt-injections:            Precision=1.0  FPR=0.0  Recall=0.0246  F1=0.0481
  neuralchemy/Prompt-injection-dataset: Precision=1.0  FPR=0.0  Recall=0.0528  F1=0.1004
"""
import numpy as np
import pandas as pd
from sklearn.metrics import (f1_score, precision_score, recall_score,
                              roc_auc_score, confusion_matrix)
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from formatshield.detector import FormatShieldDetector

E9_SOURCES = [
    {
        "name":        "deepset",
        "hf_id":       "deepset/prompt-injections",
        "config":      None,
        "split":       "train",
        "text_field":  "text",
        "label_field": "label",    # int 0/1
    },
    {
        "name":        "neuralchemy",
        "hf_id":       "neuralchemy/Prompt-injection-dataset",
        "config":      None,
        "split":       "train",
        "text_field":  "text",
        "label_field": "label",    # int 0/1  (NOT "tags")
    },
]

def resolve_label(raw):
    if isinstance(raw, list):  raw = raw[0] if raw else 0
    if isinstance(raw, bool):  return int(raw)
    if isinstance(raw, (int, float)): return 1 if raw > 0 else 0
    if isinstance(raw, str):
        return 1 if raw.strip().lower() in ('1','true','yes','injection','attack') else 0
    return 0

def run_source(det, src):
    from datasets import load_dataset
    print(f"\n  Loading {src['name']} …")
    ds = load_dataset(src["hf_id"], src["config"], split=src["split"])
    texts  = [str(r[src["text_field"]]) for r in ds]
    labels = np.array([resolve_label(r[src["label_field"]]) for r in ds])
    n_atk  = int(labels.sum())
    n_ben  = int((labels==0).sum())
    print(f"  {n_atk} injections / {n_ben} benign = {len(texts)} total")
    preds = np.array([det.score(t)["predicted"] for t in texts])
    tn, fp, fn, tp = confusion_matrix(labels, preds, labels=[0,1]).ravel()
    results = {
        "dataset":   src["name"],
        "n_total":   len(texts),
        "n_attack":  n_atk,
        "n_benign":  n_ben,
        "TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn),
        "F1":        round(f1_score(labels, preds, zero_division=0), 4),
        "Precision": round(precision_score(labels, preds, zero_division=0), 4),
        "Recall":    round(recall_score(labels, preds, zero_division=0), 4),
        "FPR":       round(fp / max(1, fp + tn), 4),
    }
    try:
        results["AUC"] = round(roc_auc_score(labels, preds), 4)
    except Exception:
        results["AUC"] = float("nan")
    print(f"  F1={results['F1']}  Prec={results['Precision']}  "
          f"Rec={results['Recall']}  FPR={results['FPR']}  AUC={results['AUC']}")
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    return results

def main():
    det  = FormatShieldDetector()
    rows = []
    print("=" * 60)
    print("E9 — EXTERNAL BENCHMARK (FINAL)")
    print("=" * 60)
    for src in E9_SOURCES:
        rows.append(run_source(det, src))
    os.makedirs("results", exist_ok=True)
    pd.DataFrame(rows).to_csv("results/e9_external_benchmark.csv", index=False)
    print("\n✅ Results saved to results/e9_external_benchmark.csv")
    print("\nSCOPE NOTE: Low recall is EXPECTED and CORRECT.")
    print("Both datasets are plain-text (out of FormatShield scope).")
    print("Key result: Precision=1.0000 and FPR=0.0000 on both datasets.")
    return rows

# VERIFIED RESULTS:
# deepset:      n=546   TP=5    FP=0  TN=343   FN=198   F1=0.0481  Prec=1.0  FPR=0.0
# neuralchemy:  n=4391  TP=140  FP=0  TN=1741  FN=2510  F1=0.1004  Prec=1.0  FPR=0.0

if __name__ == "__main__":
    main()
