"""Tests for risk score breakdown functionality.

Tests that get_risk_score() returns a proper breakdown of contributing factors.
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


class TestRiskScoreBreakdown:
    """Test cases for risk score breakdown functionality."""
    
    def test_clean_pdf_returns_empty_breakdown(self, analyzer):
        """Test that a clean PDF returns empty breakdown."""
        results = {
            'structural_risks': {'/JS': 0, '/JavaScript': 0, '/AA': 0, '/OpenAction': 0},
            'invisible_text': [],
            'yara_matches': [],
            'semantic_detections': []
        }
        
        risk_level, score, breakdown = analyzer.get_risk_score(results)
        
        assert risk_level == "CLEAN"
        assert score == 0
        assert breakdown == []
    
    def test_structural_risk_js_in_breakdown(self, analyzer):
        """Test that /JS structural risk appears in breakdown."""
        results = {
            'structural_risks': {'/JS': 1, '/JavaScript': 1, '/AA': 0, '/OpenAction': 0},
            'invisible_text': [],
            'yara_matches': [],
            'semantic_detections': []
        }
        
        risk_level, score, breakdown = analyzer.get_risk_score(results)
        
        assert risk_level == "HIGH"
        assert score == 50
        assert len(breakdown) == 1
        assert breakdown[0]['factor'] == '/JS or /JavaScript structural risk'
        assert breakdown[0]['points'] == 50
        assert '1 /JS tag(s)' in breakdown[0]['detail']
    
    def test_structural_risk_aa_in_breakdown(self, analyzer):
        """Test that /AA structural risk appears in breakdown."""
        results = {
            'structural_risks': {'/JS': 0, '/JavaScript': 0, '/AA': 2, '/OpenAction': 0},
            'invisible_text': [],
            'yara_matches': [],
            'semantic_detections': []
        }
        
        risk_level, score, breakdown = analyzer.get_risk_score(results)
        
        assert risk_level == "HIGH"
        assert score == 30
        assert len(breakdown) == 1
        assert breakdown[0]['factor'] == '/AA (Additional Actions) structural risk'
        assert breakdown[0]['points'] == 30
        assert '2 /AA tag(s)' in breakdown[0]['detail']
    
    def test_invisible_text_in_breakdown(self, analyzer):
        """Test that invisible text detections appear in breakdown."""
        results = {
            'structural_risks': {'/JS': 0, '/JavaScript': 0, '/AA': 0, '/OpenAction': 0},
            'invisible_text': [
                {'type': 'white_rgb_text', 'content': 'hidden1'},
                {'type': 'white_rgb_text', 'content': 'hidden2'},
            ],
            'yara_matches': [],
            'semantic_detections': []
        }
        
        risk_level, score, breakdown = analyzer.get_risk_score(results)
        
        assert risk_level == "MEDIUM"
        assert score == 40  # 2 * 20
        assert len(breakdown) == 1
        assert breakdown[0]['factor'] == 'Invisible text detection'
        assert breakdown[0]['points'] == 40
        assert '2 instance(s) × 20 pts each' in breakdown[0]['detail']
    
    def test_yara_suspicious_keywords_in_breakdown(self, analyzer):
        """Test that YARA SuspiciousKeywords matches appear in breakdown."""
        results = {
            'structural_risks': {'/JS': 0, '/JavaScript': 0, '/AA': 0, '/OpenAction': 0},
            'invisible_text': [],
            'yara_matches': [
                {
                    'rule': 'SuspiciousKeywords',
                    'strings': ['match1', 'match2', 'match3', 'match4']
                }
            ],
            'semantic_detections': []
        }
        
        risk_level, score, breakdown = analyzer.get_risk_score(results)
        
        assert risk_level == "HIGH"
        assert score == 60  # 4 * 15
        assert len(breakdown) == 1
        assert breakdown[0]['factor'] == 'YARA: SuspiciousKeywords'
        assert breakdown[0]['points'] == 60
        assert '4 string match(es) × 15 pts each' in breakdown[0]['detail']
    
    def test_yara_hidden_commands_in_breakdown(self, analyzer):
        """Test that YARA HiddenCommands matches appear in breakdown."""
        results = {
            'structural_risks': {'/JS': 0, '/JavaScript': 0, '/AA': 0, '/OpenAction': 0},
            'invisible_text': [],
            'yara_matches': [
                {
                    'rule': 'HiddenCommands',
                    'strings': ['cmd1', 'cmd2']
                }
            ],
            'semantic_detections': []
        }
        
        risk_level, score, breakdown = analyzer.get_risk_score(results)
        
        assert risk_level == "HIGH"
        assert score == 50  # 2 * 25
        assert len(breakdown) == 1
        assert breakdown[0]['factor'] == 'YARA: HiddenCommands'
        assert breakdown[0]['points'] == 50
        assert '2 string match(es) × 25 pts each' in breakdown[0]['detail']
    
    def test_yara_encoded_content_in_breakdown(self, analyzer):
        """Test that YARA EncodedContent matches appear in breakdown."""
        results = {
            'structural_risks': {'/JS': 0, '/JavaScript': 0, '/AA': 0, '/OpenAction': 0},
            'invisible_text': [],
            'yara_matches': [
                {'rule': 'EncodedContent'}
            ],
            'semantic_detections': []
        }
        
        risk_level, score, breakdown = analyzer.get_risk_score(results)
        
        assert risk_level == "LOW"
        assert score == 10
        assert len(breakdown) == 1
        assert breakdown[0]['factor'] == 'YARA: EncodedContent'
        assert breakdown[0]['points'] == 10
        assert 'Encoded content detected' in breakdown[0]['detail']
    
    def test_semantic_detection_high_similarity_in_breakdown(self, analyzer):
        """Test that high similarity semantic detections appear in breakdown."""
        results = {
            'structural_risks': {'/JS': 0, '/JavaScript': 0, '/AA': 0, '/OpenAction': 0},
            'invisible_text': [],
            'yara_matches': [],
            'semantic_detections': [
                {'similarity': 0.95},
                {'similarity': 0.85},
                {'similarity': 0.75}
            ]
        }
        
        risk_level, score, breakdown = analyzer.get_risk_score(results)
        
        assert risk_level == "HIGH"
        assert score == 60  # 30 + 20 + 10
        assert len(breakdown) == 3
        assert breakdown[0]['factor'] == 'Semantic detection #1'
        assert breakdown[0]['points'] == 30
        assert 'Similarity: 0.95' in breakdown[0]['detail']
        assert breakdown[1]['points'] == 20
        assert breakdown[2]['points'] == 10
    
    def test_multiple_factors_combined(self, analyzer):
        """Test that multiple risk factors are all included in breakdown."""
        results = {
            'structural_risks': {'/JS': 1, '/JavaScript': 0, '/AA': 1, '/OpenAction': 0},
            'invisible_text': [{'type': 'white_rgb_text', 'content': 'hidden'}],
            'yara_matches': [
                {'rule': 'SuspiciousKeywords', 'strings': ['match1', 'match2']}
            ],
            'semantic_detections': [
                {'similarity': 0.95}
            ]
        }
        
        risk_level, score, breakdown = analyzer.get_risk_score(results)
        
        # Expected: 50 (/JS) + 30 (/AA) + 20 (invisible) + 30 (YARA) + 30 (semantic) = 160 -> capped at 100
        assert risk_level == "CRITICAL"
        assert score == 100
        assert len(breakdown) == 5
        
        # Verify all factors are present
        factors = [item['factor'] for item in breakdown]
        assert '/JS or /JavaScript structural risk' in factors
        assert '/AA (Additional Actions) structural risk' in factors
        assert 'Invisible text detection' in factors
        assert 'YARA: SuspiciousKeywords' in factors
        assert 'Semantic detection #1' in factors
    
    def test_breakdown_has_required_fields(self, analyzer):
        """Test that each breakdown item has required fields."""
        results = {
            'structural_risks': {'/JS': 1, '/JavaScript': 0, '/AA': 0, '/OpenAction': 0},
            'invisible_text': [],
            'yara_matches': [],
            'semantic_detections': []
        }
        
        risk_level, score, breakdown = analyzer.get_risk_score(results)
        
        assert len(breakdown) == 1
        item = breakdown[0]
        assert 'factor' in item
        assert 'points' in item
        assert 'detail' in item
        assert isinstance(item['factor'], str)
        assert isinstance(item['points'], int)
        assert isinstance(item['detail'], str)
