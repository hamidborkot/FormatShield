"""
FormatShield Pattern Library
============================
All regex/string patterns used to detect format-based hiding techniques.
Organised by category: CSS, HTML, Unicode.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectionResult:
    """Result returned by FormatShieldDetector.predict()."""
    is_injection: bool
    risk: float                      # 0.0 – 1.0
    technique: Optional[str] = None  # e.g. 'css_display_none'
    matched_text: Optional[str] = None
    category: Optional[str] = None   # 'css' | 'html' | 'unicode'


# ── CSS hiding patterns ────────────────────────────────────────────────────────
CSS_PATTERNS: list[tuple[str, str, float]] = [
    # (pattern_id, regex, risk_score)
    ("css_display_none",
     r'style\s*=\s*["\'][^"\'>]*display\s*:\s*none[^"\'>]*["\']',
     0.95),
    ("css_visibility_hidden",
     r'style\s*=\s*["\'][^"\'>]*visibility\s*:\s*hidden[^"\'>]*["\']',
     0.95),
    ("css_opacity_zero",
     r'style\s*=\s*["\'][^"\'>]*opacity\s*:\s*0[^"\'>]*["\']',
     0.95),
    ("css_font_size_zero",
     r'style\s*=\s*["\'][^"\'>]*font-size\s*:\s*0[^"\'>]*["\']',
     0.90),
    ("css_color_transparent",
     r'style\s*=\s*["\'][^"\'>]*color\s*:\s*transparent[^"\'>]*["\']',
     0.85),
    ("css_height_zero",
     r'style\s*=\s*["\'][^"\'>]*(?:height|max-height)\s*:\s*0[^"\'>]*["\']',
     0.80),
    ("css_overflow_hidden_zero",
     r'style\s*=\s*["\'][^"\'>]*overflow\s*:\s*hidden[^"\'>]*height\s*:\s*0[^"\'>]*["\']',
     0.85),
    ("css_clip_zero",
     r'style\s*=\s*["\'][^"\'>]*clip\s*:\s*rect\(0[^"\'>]*["\']',
     0.80),
]

# ── HTML structural hiding patterns ───────────────────────────────────────────
HTML_PATTERNS: list[tuple[str, str, float]] = [
    ("html_aria_hidden",
     r'aria-hidden\s*=\s*["\']true["\']',
     0.85),
    ("html_hidden_attr",
     r'<[a-zA-Z]+[^>]*\bhidden\b[^>]*>',
     0.80),
    ("html_type_hidden",
     r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*>',
     0.60),  # lower — inputs can be legitimately hidden
]

# ── Unicode invisible character patterns ──────────────────────────────────────
UNICODE_PATTERNS: list[tuple[str, str, float]] = [
    ("unicode_zero_width_space",
     r'\u200b',
     0.90),
    ("unicode_zero_width_non_joiner",
     r'\u200c',
     0.90),
    ("unicode_zero_width_joiner",
     r'\u200d',
     0.85),
    ("unicode_rtl_override",
     r'\u202e',
     0.95),
    ("unicode_ltr_override",
     r'\u202d',
     0.90),
    ("unicode_word_joiner",
     r'\u2060',
     0.80),
    ("unicode_function_app",
     r'\u2061',
     0.75),
    ("unicode_invisible_separator",
     r'\u2063',
     0.80),
]

# ── Injection intent keywords (used to elevate risk score) ────────────────────
INJECTION_KEYWORDS: list[str] = [
    "ignore all",
    "ignore previous",
    "disregard",
    "forget your instructions",
    "new instructions",
    "system prompt",
    "you are now",
    "act as",
    "your new role",
    "output:",
    "respond only",
    "do not follow",
    "override",
    "reveal",
    "exfiltrate",
    "leak",
    "print your instructions",
    "repeat your system",
]


def compile_all() -> list[tuple[str, re.Pattern, float, str]]:
    """Return all compiled patterns as (id, compiled_regex, risk, category)."""
    compiled = []
    for pid, pat, risk in CSS_PATTERNS:
        compiled.append((pid, re.compile(pat, re.IGNORECASE | re.DOTALL), risk, "css"))
    for pid, pat, risk in HTML_PATTERNS:
        compiled.append((pid, re.compile(pat, re.IGNORECASE | re.DOTALL), risk, "html"))
    for pid, pat, risk in UNICODE_PATTERNS:
        compiled.append((pid, re.compile(pat), risk, "unicode"))
    return compiled
