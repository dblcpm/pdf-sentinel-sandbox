"""
Backward-compatibility shim.
Imports PDFAnalyzer from the pdf_sentinel package so existing code
(e.g. `from analyzer import PDFAnalyzer`) keeps working.
"""

from pdf_sentinel.analyzer import PDFAnalyzer  # noqa: F401

__all__ = ["PDFAnalyzer"]
