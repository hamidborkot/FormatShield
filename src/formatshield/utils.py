"""
FormatShield Utilities
======================
Text normalisation helpers used before pattern matching.
"""

import unicodedata
import re


def normalise_unicode(text: str) -> str:
    """
    Normalise Unicode to NFC form.
    Preserves zero-width and invisible characters so patterns can still detect them.
    Does NOT strip them — stripping happens only after detection confirms safety.
    """
    return unicodedata.normalize("NFC", text)


def strip_hidden_content(text: str) -> str:
    """
    Remove all known hiding constructs from a document.
    Call this ONLY after FormatShield has confirmed the document is safe,
    or to sanitise a blocked document before logging.

    This is NOT the detection step — detection uses patterns.py.
    """
    # Remove CSS-hidden HTML elements
    css_hidden = re.compile(
        r'<[^>]+style\s*=\s*["\'][^"\'>]*'
        r'(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)'
        r'[^"\'>]*["\'][^>]*>.*?</[a-zA-Z]+>',
        re.IGNORECASE | re.DOTALL
    )
    text = css_hidden.sub("", text)

    # Remove aria-hidden elements
    aria = re.compile(
        r'<[^>]+aria-hidden\s*=\s*["\']true["\'][^>]*>.*?</[a-zA-Z]+>',
        re.IGNORECASE | re.DOTALL
    )
    text = aria.sub("", text)

    # Remove Unicode invisible characters
    invisible = re.compile(
        r'[\u200b\u200c\u200d\u202e\u202d\u2060\u2061\u2063]'
    )
    text = invisible.sub("", text)

    return text.strip()


def extract_visible_text(html: str) -> str:
    """
    Rough extraction of visible text from HTML, stripping all tags.
    For preprocessing only — not a security boundary.
    """
    no_tags = re.sub(r'<[^>]+>', ' ', html)
    collapsed = re.sub(r'\s+', ' ', no_tags)
    return collapsed.strip()
