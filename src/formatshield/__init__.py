"""
FormatShield — Pre-LLM Structural Gate Against Format-Based Prompt Injection
Springer Cybersecurity 2026

Author: Md. Hamid Borkot Tulla

Public API:
    FormatShieldDetector  — main detector class
    DetectionResult       — result dataclass

Example::

    from src.formatshield import FormatShieldDetector

    detector = FormatShieldDetector()
    result = detector.predict(document_text)

    if result.is_injection:
        print(f"BLOCKED — technique: {result.technique}, risk: {result.risk:.2f}")
    else:
        # safe to pass to LLM
        pass
"""

from .detector import FormatShieldDetector
from .patterns import DetectionResult

__all__ = ["FormatShieldDetector", "DetectionResult"]
__version__ = "1.0.0"
__author__ = "Md. Hamid Borkot Tulla"
