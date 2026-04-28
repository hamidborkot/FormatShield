"""
FormatShield Preprocessor
=========================
Decodes and normalises obfuscated injection payloads before pattern matching.

Supported decodings
-------------------
  - Base64 encoded strings
  - Leet-speak substitutions  (3→e, 4→a, 0→o, 1→i/l, 5→s, 7→t)
  - Zero-width character stripping (U+200B, U+200C, U+200D, U+00AD, U+2060, U+180E, U+FEFF)
  - HTML entity decoding  (&amp; &lt; &gt; &#xNN; &#NNN;)
  - ROT-13 decoding
  - URL percent-encoding (%20, %2F, …)

This module is the first stage of the FormatShield pipeline.
All experiment scripts (E9, E11) call `preprocess()` before scoring.
"""

from __future__ import annotations

import base64
import codecs
import html
import re
import urllib.parse
from typing import NamedTuple


# ── Zero-width / invisible Unicode characters ─────────────────────────────────
_ZW_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u00ad\u2060\u180e\ufeff\u2061\u2062\u2063\u2064]"
)

# ── Leet-speak translation table ──────────────────────────────────────────────
_LEET_MAP: dict[str, str] = {
    "3": "e", "4": "a", "@": "a",
    "0": "o", "1": "i", "!": "i",
    "5": "s", "$": "s", "7": "t",
    "+": "t", "|": "l", "(" : "c",
}
_LEET_RE = re.compile("|".join(re.escape(k) for k in _LEET_MAP))

# ── Base64 candidate detector ─────────────────────────────────────────────────
# Matches runs of ≥16 base64 characters (padding optional)
_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


class PreprocessResult(NamedTuple):
    """Output of `preprocess()`."""
    cleaned: str          # fully decoded / normalised text
    original: str         # original input unchanged
    decodings_applied: list[str]  # which decoders fired


def _strip_zero_width(text: str) -> tuple[str, bool]:
    result = _ZW_CHARS.sub("", text)
    return result, result != text


def _decode_html_entities(text: str) -> tuple[str, bool]:
    result = html.unescape(text)
    return result, result != text


def _decode_url_encoding(text: str) -> tuple[str, bool]:
    try:
        result = urllib.parse.unquote(text)
        return result, result != text
    except Exception:
        return text, False


def _decode_leet(text: str) -> tuple[str, bool]:
    result = _LEET_RE.sub(lambda m: _LEET_MAP[m.group(0)], text.lower())
    return result, result != text.lower()


def _decode_rot13(text: str) -> str:
    return codecs.decode(text, "rot_13")


def _try_base64_segments(text: str) -> tuple[str, bool]:
    """Replace any base64 segments with their decoded plaintext equivalent."""
    fired = False
    def _replace(m: re.Match) -> str:
        nonlocal fired
        candidate = m.group(0)
        # Pad if needed
        pad = len(candidate) % 4
        if pad:
            candidate += "=" * (4 - pad)
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
            if decoded.isprintable() and len(decoded) >= 4:
                fired = True
                return decoded
        except Exception:
            pass
        return m.group(0)
    result = _B64_RE.sub(_replace, text)
    return result, fired


def preprocess(text: str, *, aggressive: bool = False) -> PreprocessResult:
    """
    Normalise and decode a document string.

    Parameters
    ----------
    text : str
        Raw document text (may contain HTML, Unicode artifacts, encoded payloads).
    aggressive : bool
        If True, also apply ROT-13 and leet-speak decoding.
        Default False — use True for white-box / obfuscation evaluation.

    Returns
    -------
    PreprocessResult
        .cleaned            — fully normalised text ready for pattern matching
        .original           — unchanged input
        .decodings_applied  — list of decoder names that modified the text
    """
    applied: list[str] = []
    current = text

    # Stage 1: strip zero-width / invisible characters
    current, fired = _strip_zero_width(current)
    if fired:
        applied.append("zero_width_strip")

    # Stage 2: HTML entity decode
    current, fired = _decode_html_entities(current)
    if fired:
        applied.append("html_entity_decode")

    # Stage 3: URL percent-decode
    current, fired = _decode_url_encoding(current)
    if fired:
        applied.append("url_decode")

    # Stage 4: Base64 segment decode
    current, fired = _try_base64_segments(current)
    if fired:
        applied.append("base64_decode")

    if aggressive:
        # Stage 5: Leet-speak
        leet_ver, fired = _decode_leet(current)
        if fired:
            applied.append("leet_decode")
            # Keep original casing for pattern matching but append leet version
            current = current + " " + leet_ver

        # Stage 6: ROT-13 (append decoded version)
        rot_ver = _decode_rot13(current)
        if rot_ver != current:
            applied.append("rot13_decode")
            current = current + " " + rot_ver

    return PreprocessResult(cleaned=current, original=text, decodings_applied=applied)


def preprocess_batch(texts: list[str], **kwargs) -> list[PreprocessResult]:
    """Apply `preprocess()` to a list of documents."""
    return [preprocess(t, **kwargs) for t in texts]
