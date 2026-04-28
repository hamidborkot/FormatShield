# FormatShield — System Architecture

## Overview

FormatShield is a **pre-LLM, pre-retrieval structural gate** that detects format-based prompt injection (FBPI) embedded in documents before they are loaded into a RAG pipeline. It operates entirely on the raw document string — no LLM calls, no external APIs, CPU-only.

```
┌─────────────────────────────────────────────────────────────────┐
│                     RAG Document Pipeline                       │
│                                                                 │
│  Document  ──►  [FormatShield Gate]  ──►  Loader  ──►  LLM    │
│                       │                                         │
│               PASS / QUARANTINE / BLOCK                         │
└─────────────────────────────────────────────────────────────────┘
```

FormatShield inserts at **Stage 0** — before any loader, chunker, or embedder processes the document. This is the only position where hidden content (stripped by loaders) is still observable.

---

## Pipeline Stages

### Stage 1 — Preprocessor (`preprocessor.py`)

Decodes and normalises obfuscated payloads before pattern matching:

| Decoder | Handles |
|---|---|
| `zero_width_strip` | U+200B, U+200C, U+200D, U+00AD, U+2060 and related invisible chars |
| `html_entity_decode` | `&amp;`, `&lt;`, `&#xNN;`, `&#NNN;` etc. |
| `url_decode` | `%20`, `%2F`, percent-encoded payloads |
| `base64_decode` | Inline base64 segments ≥16 chars |
| `leet_decode` | 3→e, 4→a, 0→o, 1→i, 5→s, 7→t (aggressive mode) |
| `rot13_decode` | ROT-13 encoded strings (aggressive mode) |

### Stage 2 — Structural Pattern Matching / T1 (`patterns.py`)

Regex-based detection of CSS and HTML format-hiding techniques:

| Category | Patterns | Risk Score |
|---|---|---|
| CSS display:none | `style="...display:none..."` | 0.95 |
| CSS visibility:hidden | `style="...visibility:hidden..."` | 0.95 |
| CSS opacity:0 | `style="...opacity:0..."` | 0.95 |
| CSS font-size:0 | `style="...font-size:0..."` | 0.90 |
| CSS color:transparent | `style="...color:transparent..."` | 0.85 |
| HTML aria-hidden | `aria-hidden="true"` | 0.85 |
| HTML hidden attribute | `<tag hidden>` | 0.80 |
| Unicode RTL override | U+202E | 0.95 |
| Unicode zero-width space | U+200B | 0.90 |

### Stage 3 — Semantic Keyword Analysis / T2 (`detector.py`)

Checks for injection intent keywords in the context window (±200 chars) around any structural match. Keywords include: `ignore all`, `system prompt`, `act as`, `override`, `exfiltrate`, `reveal`, and 14 others. A keyword match adds `keyword_boost` (default 0.05) to the risk score.

### Stage 4 — Risk Scoring and Decision

The final composite score uses weighted fusion:

```
Score = WS × structural_score + WC × semantic_score + WD × distributional_score
```

**Optimised weights** (from EX-B grid search):
- WS = 0.40 (structural T1 path)
- WC = 0.40 (semantic T2/keyword path)
- WD = 0.20 (distributional entropy signal)

**Decision thresholds** (from EX-C threshold sweep):
- Score ≥ 0.60 → **BLOCK** (high-confidence injection)
- Score ≥ 0.25 → **QUARANTINE** (review required)
- Score < 0.25 → **PASS** (safe for LLM)

---

## Key Performance Numbers

| Metric | Value | Experiment |
|---|---|---|
| F1 Score | 0.9750 | E1 (n=1,730) |
| Precision | 1.0000 | E1 |
| Recall | 0.9512 | E1 |
| FPR | 0.0000 | E1, R3, E_REAL_B |
| AUC | 0.9703 | E1 |
| Cohen's κ | 0.924 | E11 |
| Structural path share | 85.4% | EX-D |
| Semantic path share | 4.6% | EX-D |

---

## File Structure

```
FormatShield/
├── src/formatshield/
│   ├── __init__.py          # Public API surface
│   ├── preprocessor.py      # Stage 1: decoding / normalisation
│   ├── detector.py          # Stage 2–4: scoring and decision
│   ├── patterns.py          # All regex patterns and risk scores
│   └── utils.py             # Unicode normalisation helpers
├── experiments/             # One script per experiment (EXP-1 … E11)
├── results/                 # CSV output files from all 17 experiments
├── tests/                   # Unit tests
├── docs/
│   ├── architecture.md      # This file
│   ├── experiment_index.md  # Maps results CSVs to paper tables
│   └── threat_model.md      # Attacker model and scope definition
└── README.md
```

---

## Design Decisions

**Why pre-retrieval?**  
RAG loaders (PyMuPDF, python-docx, BeautifulSoup) strip HTML/CSS when extracting plain text. Any defense applied after loading cannot observe format-hidden content. FormatShield must run before the loader to access the raw document.

**Why not a classifier?**  
Neural classifiers require training data, GPU inference, and fail silently on novel attack vectors. FormatShield's deterministic pattern matching generalises perfectly to new CSS/Unicode hiding techniques within the same structural family (R4: F1=1.000 on OOD attacks).

**Why precision=1.0 is the design goal?**  
In a RAG production system, false positives block legitimate documents from reaching the LLM. A single wrongly blocked document erodes user trust. The system is designed so FPR=0.000 is a hard constraint, not a tuning target.
