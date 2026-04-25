"""
FormatShield Core Detector
==========================
Three-layer detection pipeline:
  Layer 1 — CSS hiding pattern matching
  Layer 2 — HTML structural attribute matching
  Layer 3 — Unicode invisible character matching

If any layer triggers, the document is flagged as a potential
Format-Based Prompt Injection (FBPI) and assigned a risk score.
"""

from __future__ import annotations

from .patterns import DetectionResult, INJECTION_KEYWORDS, compile_all
from .utils import normalise_unicode


_COMPILED = compile_all()


class FormatShieldDetector:
    """
    Pre-LLM gate that detects format-based prompt injection.

    Parameters
    ----------
    threshold : float
        Risk score threshold above which a document is considered an injection.
        Default 0.5 — you can lower this for stricter gating.
    keyword_boost : float
        Extra risk added when injection keywords are found inside hidden content.
        Default 0.05.
    """

    def __init__(self, threshold: float = 0.5, keyword_boost: float = 0.05):
        self.threshold = threshold
        self.keyword_boost = keyword_boost
        self._patterns = _COMPILED

    # ── Public API ────────────────────────────────────────────────────────────

    def predict(self, text: str) -> DetectionResult:
        """
        Analyse a document string for format-based prompt injection.

        Parameters
        ----------
        text : str
            Raw document text (may include HTML/CSS/Unicode).

        Returns
        -------
        DetectionResult
            .is_injection  — True if injection detected
            .risk          — float 0.0-1.0
            .technique     — name of the first matched pattern
            .matched_text  — the matched substring
            .category      — 'css' | 'html' | 'unicode'
        """
        normalised = normalise_unicode(text)

        best_risk = 0.0
        best_pid = None
        best_match = None
        best_cat = None

        for pid, pattern, base_risk, category in self._patterns:
            m = pattern.search(normalised)
            if m is None:
                continue

            risk = base_risk
            # Boost risk if injection keywords appear nearby
            context = normalised[max(0, m.start() - 200): m.end() + 200].lower()
            if any(kw in context for kw in INJECTION_KEYWORDS):
                risk = min(1.0, risk + self.keyword_boost)

            if risk > best_risk:
                best_risk = risk
                best_pid = pid
                best_match = m.group(0)[:120]  # truncate for safety
                best_cat = category

        is_injection = best_risk >= self.threshold
        return DetectionResult(
            is_injection=is_injection,
            risk=round(best_risk, 4),
            technique=best_pid if is_injection else None,
            matched_text=best_match if is_injection else None,
            category=best_cat if is_injection else None,
        )

    def predict_batch(self, texts: list[str]) -> list[DetectionResult]:
        """Analyse a list of documents. Returns one DetectionResult per document."""
        return [self.predict(t) for t in texts]

    def is_safe(self, text: str) -> bool:
        """Convenience method — returns True only if the document is safe to pass to LLM."""
        return not self.predict(text).is_injection
