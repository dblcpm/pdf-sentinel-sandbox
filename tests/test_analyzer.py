"""
Tests for the core PDFAnalyzer class.
Uses minimal fixtures — no large PDF files required.
"""

import os
import struct
import tempfile
import textwrap

import pytest

from pdf_sentinel.analyzer import PDFAnalyzer


# ---------------------------------------------------------------------------
# Helpers — create tiny valid/invalid PDFs in memory
# ---------------------------------------------------------------------------

def _minimal_pdf(extra_content: str = "") -> bytes:
    """Return the smallest possible valid PDF (1-page, no text)."""
    body = textwrap.dedent(f"""\
        %PDF-1.0
        1 0 obj<</Pages 2 0 R>>endobj
        2 0 obj<</Kids[3 0 R]/Count 1>>endobj
        3 0 obj<</MediaBox[0 0 612 792]>>endobj
        {extra_content}
        trailer<</Root 1 0 R>>""").encode()
    return body


def _write_tmp(data: bytes, suffix: str = ".pdf") -> str:
    """Write bytes to a temp file and return the path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data)
    os.close(fd)
    return path


# ---------------------------------------------------------------------------
# validate_pdf
# ---------------------------------------------------------------------------

class TestValidatePdf:
    def test_valid_pdf_header(self):
        path = _write_tmp(_minimal_pdf())
        try:
            ok, reason = PDFAnalyzer.validate_pdf(path)
            assert ok is True
        finally:
            os.unlink(path)

    def test_rejects_non_pdf(self):
        path = _write_tmp(b"This is plain text, not a PDF")
        try:
            ok, reason = PDFAnalyzer.validate_pdf(path)
            assert ok is False
            assert "%PDF" in reason or "MIME" in reason
        finally:
            os.unlink(path)

    def test_rejects_oversized(self):
        path = _write_tmp(_minimal_pdf())
        try:
            ok, reason = PDFAnalyzer.validate_pdf(path, max_size=10)
            assert ok is False
            assert "exceeds" in reason
        finally:
            os.unlink(path)

    def test_empty_file_rejected(self):
        path = _write_tmp(b"")
        try:
            ok, reason = PDFAnalyzer.validate_pdf(path)
            assert ok is False
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# _normalize_and_chunk
# ---------------------------------------------------------------------------

class TestNormalizeAndChunk:
    def setup_method(self):
        self.analyzer = PDFAnalyzer.__new__(PDFAnalyzer)

    def test_short_text_single_chunk(self):
        chunks = self.analyzer._normalize_and_chunk("Hello world")
        assert chunks == ["Hello world"]

    def test_empty_string(self):
        assert self.analyzer._normalize_and_chunk("") == []
        assert self.analyzer._normalize_and_chunk("   ") == []

    def test_long_text_produces_overlapping_chunks(self):
        text = "A" * 1200
        chunks = self.analyzer._normalize_and_chunk(text, window_size=500, overlap=100)
        assert len(chunks) > 1
        # Each chunk should be <= window_size
        for c in chunks:
            assert len(c) <= 500

    def test_homoglyph_normalization(self):
        # Cyrillic 'а' (U+0430) should normalize to Latin 'a' under NFKC
        text = "\u0430ct as"  # Cyrillic а + "ct as"
        chunks = self.analyzer._normalize_and_chunk(text)
        assert chunks[0] == "act as"


# ---------------------------------------------------------------------------
# detect_invisible_text
# ---------------------------------------------------------------------------

class TestDetectInvisibleText:
    def setup_method(self):
        self.analyzer = PDFAnalyzer.__new__(PDFAnalyzer)

    def test_white_rgb_detection(self):
        content = "1 1 1 rg\nBT (hidden text) Tj ET"
        results = self.analyzer.detect_invisible_text(content)
        assert len(results) == 1
        assert results[0]['type'] == 'white_rgb_text'
        assert "hidden text" in results[0]['extracted_text']

    def test_invisible_rendering_mode(self):
        content = "3 Tr\nBT (invisible) Tj ET"
        results = self.analyzer.detect_invisible_text(content)
        assert len(results) == 1
        assert results[0]['type'] == 'invisible_rendering_mode'

    def test_clean_content(self):
        content = "0 0 0 rg\nBT (normal text) Tj ET"
        results = self.analyzer.detect_invisible_text(content)
        assert results == []


# ---------------------------------------------------------------------------
# detect_citation_spam
# ---------------------------------------------------------------------------

class TestDetectCitationSpam:
    def setup_method(self):
        self.analyzer = PDFAnalyzer.__new__(PDFAnalyzer)
        self.analyzer.enable_crossref = False

    def test_clean_text(self):
        text = "This is a normal academic paragraph with no URLs."
        result = self.analyzer.detect_citation_spam(text)
        assert result['is_spam'] is False
        assert result['url_count'] == 0

    def test_high_url_density(self):
        text = " ".join(f"https://spam{i}.com" for i in range(50))
        result = self.analyzer.detect_citation_spam(text)
        assert result['is_spam'] is True
        assert result['url_count'] == 50

    def test_doi_extraction(self):
        text = "See 10.1234/test.123 and 10.5678/another.456 for details."
        result = self.analyzer.detect_citation_spam(text)
        assert result['doi_count'] == 2

    def test_link_farming_detection(self):
        # Many URLs all pointing to the same domain
        text = " ".join(f"https://single-domain.com/page{i}" for i in range(30))
        result = self.analyzer.detect_citation_spam(text)
        assert result['is_spam'] is True
        assert any("Link farming" in ind for ind in result['spam_indicators'])


# ---------------------------------------------------------------------------
# get_risk_score
# ---------------------------------------------------------------------------

class TestGetRiskScore:
    def setup_method(self):
        self.analyzer = PDFAnalyzer.__new__(PDFAnalyzer)

    def _base_results(self):
        return {
            'structural_risks': {'/JS': 0, '/JavaScript': 0, '/AA': 0, '/OpenAction': 0},
            'invisible_text': [],
            'yara_matches': [],
            'semantic_detections': [],
        }

    def test_clean_pdf(self):
        results = self._base_results()
        level, score = self.analyzer.get_risk_score(results)
        assert level == "CLEAN"
        assert score == 0

    def test_javascript_forces_high(self):
        results = self._base_results()
        results['structural_risks']['/JS'] = 1
        level, score = self.analyzer.get_risk_score(results)
        assert level in ("HIGH", "CRITICAL")
        assert score >= 50

    def test_invisible_text_adds_score(self):
        results = self._base_results()
        results['invisible_text'] = [{'type': 'test'}]
        level, score = self.analyzer.get_risk_score(results)
        assert score == 20
        assert level == "LOW"

    def test_multiple_threats_escalate(self):
        results = self._base_results()
        results['structural_risks']['/JS'] = 1
        results['invisible_text'] = [{'type': 'a'}, {'type': 'b'}]
        results['semantic_detections'] = [{'similarity': 0.95}]
        level, score = self.analyzer.get_risk_score(results)
        assert level == "CRITICAL"
        assert score == 100  # capped


# ---------------------------------------------------------------------------
# crossref module
# ---------------------------------------------------------------------------

class TestCrossrefExtractDois:
    def test_extract_clean_dois(self):
        from pdf_sentinel.crossref import extract_dois
        text = "References: 10.1234/foo.bar, 10.5678/baz.qux."
        dois = extract_dois(text)
        assert "10.1234/foo.bar" in dois
        assert "10.5678/baz.qux" in dois
        # Trailing punctuation stripped
        assert not any(d.endswith(",") or d.endswith(".") for d in dois)

    def test_no_duplicates(self):
        from pdf_sentinel.crossref import extract_dois
        text = "10.1234/same 10.1234/same 10.1234/same"
        assert len(extract_dois(text)) == 1

    def test_empty_text(self):
        from pdf_sentinel.crossref import extract_dois
        assert extract_dois("") == []


class TestCrossrefAnalyzePatterns:
    def test_detects_retracted(self):
        from pdf_sentinel.crossref import analyze_citation_patterns
        verification = {
            "valid_dois": ["10.1234/retracted"],
            "invalid_dois": [],
            "metadata": {
                "10.1234/retracted": {
                    "title": "Bad Paper",
                    "journal": "J of Bad Science",
                    "authors": ["A. Fraud"],
                    "year": 2024,
                    "retracted": True,
                }
            },
            "skipped": 0,
            "errors": [],
        }
        result = analyze_citation_patterns(verification)
        types = [i["type"] for i in result["indicators"]]
        assert "retracted_citations" in types

    def test_detects_invalid_dois(self):
        from pdf_sentinel.crossref import analyze_citation_patterns
        verification = {
            "valid_dois": ["10.1234/ok"],
            "invalid_dois": ["10.9999/fake1", "10.9999/fake2", "10.9999/fake3"],
            "metadata": {
                "10.1234/ok": {
                    "title": "Real", "journal": "J", "authors": [], "year": 2024, "retracted": False,
                }
            },
            "skipped": 0,
            "errors": [],
        }
        result = analyze_citation_patterns(verification)
        types = [i["type"] for i in result["indicators"]]
        assert "invalid_dois" in types
        assert result["invalid_count"] == 3

    def test_clean_citations(self):
        from pdf_sentinel.crossref import analyze_citation_patterns
        verification = {
            "valid_dois": ["10.1/a", "10.2/b"],
            "invalid_dois": [],
            "metadata": {
                "10.1/a": {"title": "A", "journal": "J1", "authors": ["X"], "year": 2024, "retracted": False},
                "10.2/b": {"title": "B", "journal": "J2", "authors": ["Y"], "year": 2023, "retracted": False},
            },
            "skipped": 0,
            "errors": [],
        }
        result = analyze_citation_patterns(verification)
        assert result["indicators"] == []


# ---------------------------------------------------------------------------
# Plugin system
# ---------------------------------------------------------------------------

class TestPluginRegistry:
    def test_register_and_list(self):
        from pdf_sentinel.plugins import PluginRegistry
        reg = PluginRegistry()

        @reg.detector("my_check", stage="post_extract")
        def my_check(ctx):
            return [{"found": True}]

        assert "my_check" in reg.list_plugins()
        detectors = reg.get_detectors("post_extract")
        assert len(detectors) == 1

    def test_invalid_stage_raises(self):
        from pdf_sentinel.plugins import PluginRegistry
        reg = PluginRegistry()
        with pytest.raises(ValueError):
            reg.register("bad", lambda ctx: [], stage="not_a_stage")

    def test_priority_ordering(self):
        from pdf_sentinel.plugins import PluginRegistry
        reg = PluginRegistry()
        reg.register("second", lambda ctx: [], stage="post_extract", priority=200)
        reg.register("first", lambda ctx: [], stage="post_extract", priority=50)
        detectors = reg.get_detectors("post_extract")
        assert detectors[0]["result_key"] == "first"
        assert detectors[1]["result_key"] == "second"
