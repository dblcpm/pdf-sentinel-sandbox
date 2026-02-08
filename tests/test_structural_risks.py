"""Tests for detect_structural_risks using the pdfid library.

Uses a lightweight stub that avoids importing heavy dependencies (torch, etc.)
by calling the detect_structural_risks method directly via the module-level
function extracted from PDFAnalyzer.
"""

import os
import sys
import tempfile
import types

import pytest


# ---------------------------------------------------------------------------
# Minimal stubs for heavy third-party packages that analyzer.py imports at
# module level.  We only need them to *exist* so the module can be imported;
# the tests below never exercise those code-paths.
# ---------------------------------------------------------------------------
_STUBS = {}
for _name in (
    "torch", "yara", "sentence_transformers", "numpy",
    "presidio_analyzer", "spacy", "PIL", "magic",
):
    if _name not in sys.modules:
        _STUBS[_name] = sys.modules[_name] = types.ModuleType(_name)

# sentence_transformers needs a SentenceTransformer attribute
if hasattr(sys.modules["sentence_transformers"], "__stub__") or "sentence_transformers" in _STUBS:
    sys.modules["sentence_transformers"].SentenceTransformer = type("SentenceTransformer", (), {})

# presidio_analyzer needs an AnalyzerEngine attribute
if hasattr(sys.modules["presidio_analyzer"], "__stub__") or "presidio_analyzer" in _STUBS:
    sys.modules["presidio_analyzer"].AnalyzerEngine = type("AnalyzerEngine", (), {})

# torch stubs
_torch = sys.modules["torch"]
if "torch" in _STUBS:
    _torch.set_num_threads = lambda x: None
    _torch.no_grad = lambda: type("ctx", (), {"__enter__": lambda s: s, "__exit__": lambda s, *a: None})()
    _torch.tensor = lambda *a, **kw: None
    _torch.device = lambda *a: None
    _torch.cuda = types.ModuleType("torch.cuda")
    _torch.cuda.is_available = lambda: False
    sys.modules["torch.cuda"] = _torch.cuda

# numpy stubs
_np = sys.modules["numpy"]
if "numpy" in _STUBS:
    _np.array = lambda *a, **kw: []
    _np.float32 = float
    _np.ndarray = type("ndarray", (), {})

# Now we can safely import the analyzer
from pdf_sentinel.analyzer import PDFAnalyzer  # noqa: E402


# ---------------------------------------------------------------------------
# Test PDF byte-strings
# ---------------------------------------------------------------------------

CLEAN_PDF = (
    b"%PDF-1.1\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
    b"xref\n0 4\n"
    b"0000000000 65535 f \n"
    b"0000000009 00000 n \n"
    b"0000000058 00000 n \n"
    b"0000000115 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF"
)

PDF_WITH_JS = (
    b"%PDF-1.1\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
    b"4 0 obj<</S/JavaScript/JS(app.alert\\('test'\\))>>endobj\n"
    b"xref\n0 5\n"
    b"0000000000 65535 f \n"
    b"0000000009 00000 n \n"
    b"0000000074 00000 n \n"
    b"0000000131 00000 n \n"
    b"0000000200 00000 n \n"
    b"trailer<</Size 5/Root 1 0 R>>\nstartxref\n260\n%%EOF"
)


@pytest.fixture
def analyzer():
    """Create a bare PDFAnalyzer without triggering __init__."""
    return PDFAnalyzer.__new__(PDFAnalyzer)


def _write_temp_pdf(content: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.write(fd, content)
    os.close(fd)
    return path


class TestDetectStructuralRisks:
    def test_clean_pdf_returns_zero_counts(self, analyzer):
        path = _write_temp_pdf(CLEAN_PDF)
        try:
            result = analyzer.detect_structural_risks(path)
            assert "error" not in result
            assert result["/JS"] == 0
            assert result["/JavaScript"] == 0
            assert result["/AA"] == 0
            assert result["/OpenAction"] == 0
        finally:
            os.unlink(path)

    def test_pdf_with_js_detects_tags(self, analyzer):
        path = _write_temp_pdf(PDF_WITH_JS)
        try:
            result = analyzer.detect_structural_risks(path)
            assert "error" not in result
            assert result["/JS"] >= 1
            assert result["/JavaScript"] >= 1
            assert result["/OpenAction"] >= 1
        finally:
            os.unlink(path)

    def test_nonexistent_file_returns_error(self, analyzer):
        result = analyzer.detect_structural_risks("/nonexistent/file.pdf")
        assert "error" in result
        assert result["/JS"] == 0

    def test_non_pdf_file_still_returns_counts(self, analyzer):
        path = _write_temp_pdf(b"This is not a PDF file")
        try:
            result = analyzer.detect_structural_risks(path)
            assert result["/JS"] == 0
            assert result["/JavaScript"] == 0
        finally:
            os.unlink(path)
