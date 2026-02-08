"""Tests for invisible text detection.

Tests the improved detect_invisible_text method that handles operators
both inside and outside BT...ET blocks.
"""

import os
import sys
import types

import pytest


# ---------------------------------------------------------------------------
# Minimal stubs for heavy third-party packages
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


@pytest.fixture
def analyzer():
    """Create a bare PDFAnalyzer without triggering __init__."""
    return PDFAnalyzer.__new__(PDFAnalyzer)


class TestInvisibleTextDetection:
    """Test cases for invisible text detection patterns."""
    
    def test_white_rgb_before_bt(self, analyzer):
        """Test detection of white RGB text with operator before BT (legacy pattern)."""
        pdf_content = b"1 1 1 rg BT /F1 12 Tf (hidden text) Tj ET"
        result = analyzer.detect_invisible_text(pdf_content.decode('latin-1'))
        
        assert len(result) >= 1
        assert any(d['type'] == 'white_rgb_text' for d in result)
        detection = next(d for d in result if d['type'] == 'white_rgb_text')
        assert 'hidden text' in detection['extracted_text']
    
    def test_white_rgb_inside_bt(self, analyzer):
        """Test detection of white RGB text with operator inside BT...ET (new pattern)."""
        pdf_content = b"BT 1 1 1 rg /F1 12 Tf (hidden text) Tj ET"
        result = analyzer.detect_invisible_text(pdf_content.decode('latin-1'))
        
        assert len(result) >= 1
        assert any(d['type'] == 'white_rgb_text' for d in result)
        detection = next(d for d in result if d['type'] == 'white_rgb_text')
        assert 'hidden text' in detection['extracted_text']
    
    def test_white_grayscale_before_bt(self, analyzer):
        """Test detection of white grayscale text with operator before BT."""
        pdf_content = b"1 g BT /F1 12 Tf (white invisible) Tj ET"
        result = analyzer.detect_invisible_text(pdf_content.decode('latin-1'))
        
        assert len(result) >= 1
        assert any(d['type'] == 'white_grayscale_text' for d in result)
        detection = next(d for d in result if d['type'] == 'white_grayscale_text')
        assert 'white invisible' in detection['extracted_text']
    
    def test_white_grayscale_inside_bt(self, analyzer):
        """Test detection of white grayscale text with operator inside BT...ET."""
        pdf_content = b"BT 1 g /F1 12 Tf (white invisible) Tj ET"
        result = analyzer.detect_invisible_text(pdf_content.decode('latin-1'))
        
        assert len(result) >= 1
        assert any(d['type'] == 'white_grayscale_text' for d in result)
        detection = next(d for d in result if d['type'] == 'white_grayscale_text')
        assert 'white invisible' in detection['extracted_text']
    
    def test_invisible_render_mode_before_bt(self, analyzer):
        """Test detection of invisible render mode with operator before BT."""
        pdf_content = b"3 Tr BT /F1 12 Tf (invisible mode) Tj ET"
        result = analyzer.detect_invisible_text(pdf_content.decode('latin-1'))
        
        assert len(result) >= 1
        assert any(d['type'] == 'invisible_rendering_mode' for d in result)
        detection = next(d for d in result if d['type'] == 'invisible_rendering_mode')
        assert 'invisible mode' in detection['extracted_text']
    
    def test_invisible_render_mode_inside_bt(self, analyzer):
        """Test detection of invisible render mode with operator inside BT...ET."""
        pdf_content = b"BT 3 Tr /F1 12 Tf (invisible mode) Tj ET"
        result = analyzer.detect_invisible_text(pdf_content.decode('latin-1'))
        
        assert len(result) >= 1
        assert any(d['type'] == 'invisible_rendering_mode' for d in result)
        detection = next(d for d in result if d['type'] == 'invisible_rendering_mode')
        assert 'invisible mode' in detection['extracted_text']
    
    def test_zero_size_font(self, analyzer):
        """Test detection of zero-size font (new pattern)."""
        pdf_content = b"BT /F1 0 Tf (zero size text) Tj ET"
        result = analyzer.detect_invisible_text(pdf_content.decode('latin-1'))
        
        assert len(result) >= 1
        assert any(d['type'] == 'zero_size_font' for d in result)
        detection = next(d for d in result if d['type'] == 'zero_size_font')
        assert 'zero size text' in detection['extracted_text']
    
    def test_black_grayscale(self, analyzer):
        """Test detection of black grayscale text (new pattern)."""
        pdf_content = b"BT 0 g /F1 12 Tf (black text) Tj ET"
        result = analyzer.detect_invisible_text(pdf_content.decode('latin-1'))
        
        assert len(result) >= 1
        assert any(d['type'] == 'black_grayscale_text' for d in result)
        detection = next(d for d in result if d['type'] == 'black_grayscale_text')
        assert 'black text' in detection['extracted_text']
    
    def test_black_rgb(self, analyzer):
        """Test detection of black RGB text (new pattern)."""
        pdf_content = b"BT 0 0 0 rg /F1 12 Tf (black rgb text) Tj ET"
        result = analyzer.detect_invisible_text(pdf_content.decode('latin-1'))
        
        assert len(result) >= 1
        assert any(d['type'] == 'black_rgb_text' for d in result)
        detection = next(d for d in result if d['type'] == 'black_rgb_text')
        assert 'black rgb text' in detection['extracted_text']
    
    def test_no_invisible_text(self, analyzer):
        """Test that normal text is not flagged as invisible."""
        pdf_content = b"BT /F1 12 Tf (normal text) Tj ET"
        result = analyzer.detect_invisible_text(pdf_content.decode('latin-1'))
        
        assert len(result) == 0
    
    def test_multiple_detections(self, analyzer):
        """Test detection of multiple invisible text patterns in same content."""
        pdf_content = b"""
        BT 1 1 1 rg /F1 12 Tf (white text) Tj ET
        BT 3 Tr /F1 12 Tf (invisible render) Tj ET
        BT /F1 0 Tf (zero size) Tj ET
        """
        result = analyzer.detect_invisible_text(pdf_content.decode('latin-1'))
        
        assert len(result) >= 3
        types_found = {d['type'] for d in result}
        assert 'white_rgb_text' in types_found
        assert 'invisible_rendering_mode' in types_found
        assert 'zero_size_font' in types_found
