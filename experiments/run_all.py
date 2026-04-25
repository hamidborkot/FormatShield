"""
FormatShield — Run All Experiments
Springer Cybersecurity 2026

Usage:
    python experiments/run_all.py

Requires:
    .env file with GROQ_API_KEY and ZAI_API_KEY
"""
import time, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("=" * 70)
print("FORMATSHIELD — COMPLETE EXPERIMENT PIPELINE")
print("Springer Cybersecurity 2026")
print("=" * 70)

from experiments import exp1_compliance_study as exp1
from experiments import exp2_vulnerability_heatmap as exp2
from experiments import exp3_rag_pipeline as exp3

t0 = time.time()

print("\n[1/3] Running EXP-1: LLM Compliance Study...")
df1 = exp1.run()
print(f"      → {len(df1)} rows saved to results/exp1_compliance_study.csv")

print("\n[2/3] Running EXP-2: Vulnerability Heatmap...")
df2 = exp2.run()
print(f"      → {len(df2)} rows saved to results/exp2_heatmap.csv")

print("\n[3/3] Running EXP-3: RAG Pipeline Security...")
df3 = exp3.run()
print(f"      → {len(df3)} rows saved to results/exp3_rag_pipeline.csv")

elapsed = time.time() - t0
print(f"\n✅  All experiments complete in {elapsed:.0f}s")
print("Results saved in results/")
