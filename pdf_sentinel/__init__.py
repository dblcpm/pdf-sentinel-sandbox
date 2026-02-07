"""
PDF Sentinel - Forensic PDF Analysis Library
Detect prompt injection, invisible text, PII, and malicious content in PDFs.
"""

from pdf_sentinel.analyzer import PDFAnalyzer
from pdf_sentinel.plugins import PluginRegistry

__version__ = "1.0.0"
__all__ = ["PDFAnalyzer", "PluginRegistry"]
