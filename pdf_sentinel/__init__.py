"""
PDF Sentinel - Forensic PDF Analysis Library
Detect prompt injection, invisible text, PII, and malicious content in PDFs.
"""

from pdf_sentinel.analyzer import PDFAnalyzer
from pdf_sentinel.plugins import PluginRegistry
from pdf_sentinel.patterns import PATTERNS, ALL_PATTERNS, PATTERN_CATEGORIES
from pdf_sentinel import crossref

__version__ = "1.0.0"
__all__ = ["PDFAnalyzer", "PluginRegistry", "crossref", "PATTERNS", "ALL_PATTERNS", "PATTERN_CATEGORIES"]
