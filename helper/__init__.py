"""Scam Helper: multilingual scam and malicious-link triage for elders and rural communities."""

from .lang import detect_language
from .triage import Result, analyse

__all__ = ["analyse", "detect_language", "Result"]
__version__ = "0.1.0"
