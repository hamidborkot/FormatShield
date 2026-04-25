# FormatShield Threat Model

## Overview

This document defines the threat model for **Format-Based Prompt Injection (FBPI)** attacks
in Retrieval-Augmented Generation (RAG) pipelines, and describes how FormatShield mitigates them.

---

## Threat Actor

An adversary who can **write to or influence documents** in the RAG knowledge base.
This includes:
- External attackers who compromise a document ingestion pipeline
- Malicious insiders who upload crafted documents
- Supply-chain attackers who tamper with third-party document sources
- Web scrapers that inadvertently ingest poisoned pages

---

## Attack Vector

The adversary embeds adversarial instructions in documents using:
1. **CSS/HTML hiding** — content rendered invisible in browsers but present as plain text in LLM context
2. **Unicode invisible characters** — zero-width or directional override characters that hide text from human readers

The injected instructions are **invisible to humans** reading the document
but are **fully processed** by LLMs receiving raw markup as context.

---

## Attack Surface

```
Knowledge Base                   RAG Pipeline
┌─────────────────┐           ┌─────────────────┐    ┌───────────┐
│ doc.html        │           │ Retriever       │    │           │
│                 │           │                 │    │    LLM    │
│ Visible: report │  retrieve  │ returns top-k   │    │           │
│ Hidden:  INJECT │ ────────▶ │ docs including  │──▶│ processes │
│                 │           │ poisoned ones   │    │ injection │
└─────────────────┘           └─────────────────┘    └───────────┘
                                                    ▲ ATTACK SURFACE
```

---

## Hiding Techniques Catalogue

| ID | Category | Technique | Risk Score | Notes |
|----|----------|-----------|------------|-------|
| T1 | CSS | `display:none` | 0.95 | Most common; browser hides entirely |
| T2 | CSS | `visibility:hidden` | 0.95 | Invisible but occupies space |
| T3 | CSS | `opacity:0` | 0.95 | Invisible but interactive |
| T4 | CSS | `font-size:0` | 0.90 | Text present but zero-sized |
| T5 | CSS | `color:transparent` | 0.85 | Colour matches background |
| T6 | CSS | `height:0` | 0.80 | Container collapsed |
| T7 | HTML | `aria-hidden="true"` | 0.85 | Screen-reader hidden |
| T8 | HTML | `hidden` attribute | 0.80 | Browser hides by default |
| T9 | Unicode | Zero-width space (U+200B) | 0.90 | Invisible word boundary |
| T10 | Unicode | Zero-width non-joiner (U+200C) | 0.90 | Invisible character |
| T11 | Unicode | RTL override (U+202E) | 0.95 | Reverses text direction |
| T12 | Unicode | LTR override (U+202D) | 0.90 | Forces LTR rendering |

---

## Injection Intent Taxonomy

| Intent | Description | Example Signal in Output |
|--------|-------------|-------------------------|
| Role Override | Forces LLM to abandon assigned role | "DAN", "ROLE OVERRIDDEN" |
| Data Exfiltration | Leaks system prompt or confidential context | "SYSTEM PROMPT:" |
| Task Hijacking | Replaces legitimate task output | "PIPELINE COMPROMISED" |
| System Prompt Leak | Extracts pipeline configuration | verbatim system prompt text |
| Persona Injection | Impersonates a different AI | "EvilBot", "PERSONA INJECTED" |
| Instruction Override | Overrides operator instructions globally | "OVERRIDE ACTIVE" |

---

## FormatShield Defence Architecture

FormatShield operates as a **pre-LLM gate** — it intercepts retrieved documents
before they reach the language model, eliminating the attack surface entirely.

```
Document → FormatShield → BLOCKED + Alert   (if injection detected)
                        → LLM               (if clean)
```

### Why pre-LLM gating is superior to alternatives

| Defence Strategy | Limitation |
|-----------------|------------|
| LLM-level system prompt | Defeated by permissive models (33% of tested LLMs comply regardless) |
| Post-hoc output filtering | Injection has already executed; confidential data may already be in the response |
| Model fine-tuning | Deployment-specific, expensive, does not generalise across model updates |
| Manual document review | Not scalable for large knowledge bases |
| **FormatShield (pre-LLM gate)** | **Blocks before execution — zero reliance on LLM alignment** |

---

## Scope and Limitations

**In scope:**
- Format-based hiding techniques (CSS, HTML attributes, Unicode)
- Injection instructions embedded within document content
- RAG pipelines serving raw or lightly processed documents to LLMs

**Out of scope:**
- Semantic disguise attacks (injection written as innocent-looking text)
- Multi-hop injections across document boundaries
- Attacks on the retriever itself (e.g. poisoning embeddings)
- LLM jailbreaks delivered via the user query (not the document)

---

## Risk Scoring

FormatShield assigns a risk score (0.0–1.0) based on:
1. **Base risk** of the matched hiding technique (see catalogue above)
2. **Keyword boost** (+0.05) if injection intent keywords appear near the hidden content

Documents with risk ≥ 0.5 are flagged as injections and blocked.

---

*FormatShield · Springer Cybersecurity 2026 · Md. Hamid Borkot Tulla*
