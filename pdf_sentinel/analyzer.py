"""
PDF Sentinel Analyzer
Core forensic analysis engine for PDF files.
"""

import os
import re
import subprocess
import tempfile
import shutil
import unicodedata
from pathlib import Path
from typing import Dict, List, Tuple, Optional, TYPE_CHECKING

import torch
import yara
from sentence_transformers import SentenceTransformer
import numpy as np
from presidio_analyzer import AnalyzerEngine

if TYPE_CHECKING:
    from pdf_sentinel.plugins import PluginRegistry

# CPU Efficiency Failsafe: Default to 2 threads to prevent container lockups
try:
    max_threads = int(os.getenv('MAX_CPU_THREADS', '2'))
    if max_threads <= 0:
        max_threads = 2
    torch.set_num_threads(max_threads)
except (ValueError, TypeError):
    torch.set_num_threads(2)

import re as _re

# ── O(n) invisible-text detection ─────────────────────────────────────
# The original detect_invisible_text() runs 6 regex patterns with re.DOTALL
# across the entire multi-MB PDF content, causing catastrophic backtracking
# — O(n²) or worse.
#
# Replacement strategy (O(n)):
#   Pass 1: extract BT…ET text blocks via str.find (linear scan)
#   Pass 2: check each small block for invisible-text markers

_INVIS_MARKERS = [
    # Match both integer (1 1 1 rg) and decimal (1.0 1.0 1.0 rg) notation.
    # Lookbehind prevents matching e.g. "11 1 1 rg" or "10 0 0 rg".
    # ── White RGB (non-stroking fill: rg) ──
    (_re.compile(r"(?<![.\d])1(?:\.0+)?\s+1(?:\.0+)?\s+1(?:\.0+)?\s+rg(?!\w)"),
     "white_rgb_text", "white_rg",
     "White text on white background (1 1 1 rg)"),

    # ── White CMYK (non-stroking fill: k) ──
    (_re.compile(r"(?<![.\d])0(?:\.0+)?\s+0(?:\.0+)?\s+0(?:\.0+)?\s+0(?:\.0+)?\s+k(?!\w)"),
     "white_cmyk_text", "white_k",
     "White text via CMYK (0 0 0 0 k)"),

    # ── White grayscale (non-stroking fill: g) ──
    (_re.compile(r"(?<![.\d])1(?:\.0+)?\s+g(?!\w)"),
     "white_grayscale_text", "white_g",
     "White grayscale text (1 g)"),

    # ── Black RGB (non-stroking fill: rg) ──
    (_re.compile(r"(?<![.\d])0(?:\.0+)?\s+0(?:\.0+)?\s+0(?:\.0+)?\s+rg(?!\w)"),
     "black_rgb_text", "black_rg",
     "Black RGB text (0 0 0 rg)"),

    # ── Black grayscale (non-stroking fill: g) ──
    (_re.compile(r"(?<![.\d])0(?:\.0+)?\s+g(?!\w)"),
     "black_grayscale_text", "black_g",
     "Black grayscale text (0 g)"),

    # ── Invisible rendering mode (3 Tr) ──
    (_re.compile(r"(?<![.\d])3\s+Tr(?!\w)"),
     "invisible_rendering_mode", "tr3",
     "Invisible text rendering mode (3 Tr)"),

    # ── Zero-size font (/F… 0 Tf) ──
    (_re.compile(r"/\w+\s+0(?:\.0+)?\s+Tf(?!\w)"),
     "zero_size_font", "zero_tf",
     "Zero-size font (0 Tf)"),
]

_INVIS_MAX_CONTENT = 10 * 1024 * 1024  # 10 MB cap
_INVIS_MAX_BLOCK = 10 * 1024           # skip BT…ET blocks > 10 KB (binary noise)
_INVIS_MAX_PER_TYPE = 50               # cap findings per marker type


def _is_pdf_operator(content: str, pos: int, op_len: int) -> bool:
    """Check that the token at *pos* is a standalone PDF operator."""
    if pos > 0 and content[pos - 1].isalnum():
        return False
    end = pos + op_len
    if end < len(content) and content[end].isalnum():
        return False
    return True


def _extract_bt_text(block: str) -> str:
    """Extract readable text from a single BT…ET block."""
    parts: list[str] = []
    for m in _re.finditer(r"\(([^)]*)\)\s*Tj", block):
        parts.append(m.group(1))
    for m in _re.finditer(r"\[([^\]]*)\]\s*TJ", block):
        for sm in _re.finditer(r"\(([^)]*)\)", m.group(1)):
            parts.append(sm.group(1))
    return " ".join(parts)


def _decompress_page_streams(pdf_path: str) -> str:
    """Extract decompressed page content streams using pypdf.

    Most PDFs use FlateDecode compression on content streams.  The raw-byte
    scan cannot see BT/ET text blocks inside compressed streams.  This
    function decompresses all pages and returns the combined content.
    """
    try:
        from pypdf import PdfReader

        reader = PdfReader(pdf_path)
        parts: list[str] = []
        for page in reader.pages:
            contents = page.get("/Contents")
            if contents is None:
                continue
            obj = contents.get_object() if hasattr(contents, "get_object") else contents
            if isinstance(obj, list):
                for item in obj:
                    stream = item.get_object() if hasattr(item, "get_object") else item
                    if hasattr(stream, "get_data"):
                        parts.append(stream.get_data().decode("latin-1", errors="replace"))
            elif hasattr(obj, "get_data"):
                parts.append(obj.get_data().decode("latin-1", errors="replace"))
        return "\n".join(parts)
    except Exception:
        return ""


def _scan_content_for_invisible_text(pdf_content: str) -> list[dict]:
    """O(n) two-pass BT/ET scan for invisible-text markers.

    Pass 1: extract BT…ET text blocks via str.find (linear scan)
    Pass 2: check each small block against compiled marker regexes
    """
    if len(pdf_content) > _INVIS_MAX_CONTENT:
        pdf_content = pdf_content[:_INVIS_MAX_CONTENT]

    findings: list[dict] = []
    counts: dict[str, int] = {}

    pos = 0
    while pos < len(pdf_content):
        bt = pdf_content.find("BT", pos)
        if bt == -1:
            break
        if not _is_pdf_operator(pdf_content, bt, 2):
            pos = bt + 2
            continue
        et = pdf_content.find("ET", bt + 2)
        if et == -1:
            break
        if not _is_pdf_operator(pdf_content, et, 2):
            pos = et + 2
            continue

        block = pdf_content[bt : et + 2]
        if len(block) > _INVIS_MAX_BLOCK:
            pos = et + 2
            continue

        # Include 200 chars of pre-context for graphics-state markers
        # set *before* the BT operator.
        ctx_start = max(0, bt - 200)
        block_with_ctx = pdf_content[ctx_start : et + 2]

        for marker_re, itype, label, desc in _INVIS_MARKERS:
            if counts.get(label, 0) >= _INVIS_MAX_PER_TYPE:
                continue
            if marker_re.search(block_with_ctx):
                text = _extract_bt_text(block)
                counts[label] = counts.get(label, 0) + 1
                findings.append({
                    "type": itype,
                    "description": f"{desc} detected",
                    "label": label,
                    "content": text[:200] if text else "",
                    "extracted_text": text[:200] if text else "",
                    "position": bt,
                })

        pos = et + 2

    return findings


def _fast_detect_invisible_text(pdf_content: str, pdf_path: str = "") -> list[dict]:
    """Drop-in replacement for PDFAnalyzer.detect_invisible_text().

    O(n) two-pass scan — no catastrophic backtracking.
    Falls back to decompressed page streams when the raw-byte scan
    finds no BT/ET blocks (common with FlateDecode-compressed PDFs).

    Parameters
    ----------
    pdf_content : str
        Raw PDF file content (may be compressed).
    pdf_path : str
        Path to the PDF file — needed for the decompression fallback.
        If empty, decompression fallback is skipped.
    """
    # First try: scan raw PDF bytes (works for uncompressed streams)
    findings = _scan_content_for_invisible_text(pdf_content)

    # If the raw scan found nothing and we have a pdf_path, try
    # decompressing page content streams (catches FlateDecode etc.)
    if not findings and pdf_path:
        decompressed = _decompress_page_streams(pdf_path)
        if decompressed:
            findings = _scan_content_for_invisible_text(decompressed)

    return findings


class PDFAnalyzer:
    """Main analyzer class for PDF forensic analysis."""

    # Maximum file size: 200 MB (prevents DoS from oversized uploads)
    MAX_FILE_SIZE = 200 * 1024 * 1024

    def __init__(
        self,
        yara_rules_path: str = "signatures.yara",
        enable_semantic: bool = True,
        enable_crossref: bool = False,
        device: Optional[str] = None,
        plugins: Optional["PluginRegistry"] = None,
    ):
        """
        Initialize the PDF analyzer.

        Args:
            yara_rules_path: Path to YARA rules file
            enable_semantic: Whether to enable semantic detection
            enable_crossref: Whether to verify DOIs against CrossRef API
                             (requires network access, adds latency)
            device: Torch device for embeddings ('cpu', 'cuda', etc.).
                    Defaults to 'cpu'. Pro/GPU deployments can pass 'cuda'.
            plugins: Optional PluginRegistry with additional detectors
        """
        self.yara_rules_path = yara_rules_path
        self.yara_rules = None
        self.embedding_model = None
        self.enable_semantic = enable_semantic
        self.enable_crossref = enable_crossref
        self.embedding_available = False
        self.pii_analyzer = None
        self.device = device or "cpu"
        self.plugins = plugins

        # Load YARA rules if file exists
        if os.path.exists(yara_rules_path):
            try:
                self.yara_rules = yara.compile(filepath=yara_rules_path)
            except Exception as e:
                print(f"Warning: Failed to load YARA rules: {e}")

        # Known malicious prompt injection patterns for semantic analysis
        from pdf_sentinel.patterns import ALL_PATTERNS, PATTERN_CATEGORIES
        self.malicious_patterns = ALL_PATTERNS
        self._pattern_categories = PATTERN_CATEGORIES

    # ------------------------------------------------------------------
    # Plugin helpers
    # ------------------------------------------------------------------

    def _run_plugins(self, stage: str, ctx: dict, results: dict):
        """Execute registered plugins for a given pipeline stage."""
        if not self.plugins:
            return
        for det in self.plugins.get_detectors(stage):
            try:
                findings = det["fn"](ctx)
                if findings:
                    results[det["result_key"]] = findings
            except Exception as e:
                results.setdefault("plugin_errors", []).append(
                    f"Plugin '{det['result_key']}' failed: {e}"
                )

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def detect_obfuscated_payloads(self, text: str) -> List[Dict[str, any]]:
        """Detect obfuscated payloads using Base64 detection."""
        import base64

        detections = []
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

        for match in base64_pattern.finditer(text):
            base64_str = match.group(0)
            try:
                decoded_bytes = base64.b64decode(base64_str, validate=True)
                decoded_text = decoded_bytes.decode('utf-8', errors='ignore')

                if len(decoded_text.strip()) < 10:
                    continue

                semantic_results = self.detect_semantic_injection(decoded_text)
                yara_results = self.scan_with_yara(decoded_text)

                if semantic_results or yara_results:
                    decoded_preview = decoded_text[:200] + ('...' if len(decoded_text) > 200 else '')
                    detections.append({
                        'type': 'obfuscated_base64',
                        'description': (
                            'Base64-encoded content was found that contains suspicious data. '
                            f'When decoded, the hidden text reads: "{decoded_preview}". '
                            'This encoding technique is often used to conceal malicious instructions '
                            'from security scanners.'
                        ),
                        'encoded': base64_str[:100] + ('...' if len(base64_str) > 100 else ''),
                        'decoded': decoded_preview,
                        'position': match.start(),
                        'semantic_matches': semantic_results,
                        'yara_matches': yara_results
                    })
            except Exception:
                continue

        return detections

    def _normalize_and_chunk(self, text: str, window_size: int = 500, overlap: int = 100) -> List[str]:
        """Normalize text (NFKC) and split into sliding windows."""
        normalized_text = unicodedata.normalize('NFKC', text)

        chunks = []
        text_length = len(normalized_text)

        if text_length < 500:
            return [normalized_text] if normalized_text.strip() else []

        start = 0
        while start < text_length:
            end = min(start + window_size, text_length)
            chunk = normalized_text[start:end]
            if chunk.strip():
                chunks.append(chunk)
            start += window_size - overlap
            if end == text_length:
                break

        return chunks

    def load_embedding_model(self):
        """Lazy load the embedding model onto the configured device."""
        if not self.enable_semantic:
            return

        if self.embedding_model is None:
            try:
                self.embedding_model = SentenceTransformer(
                    'all-MiniLM-L6-v2', device=self.device
                )
                self.embedding_available = True
            except Exception as e:
                print(f"Warning: Could not load embedding model: {e}")
                print("Semantic detection will be disabled")
                self.embedding_available = False

    def uncompress_pdf(self, pdf_path: str, output_path: str) -> Tuple[bool, str]:
        """Uncompress PDF using qpdf for analysis."""
        try:
            cmd = [
                'qpdf', '--qdf', '--object-streams=disable',
                pdf_path, output_path
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0 and os.path.exists(output_path):
                if result.stderr and 'WARNING' in result.stderr:
                    return True, f"PDF uncompressed with warnings: {result.stderr[:200]}"
                return True, "PDF uncompressed successfully"
            elif result.returncode == 3:
                if os.path.exists(output_path):
                    return True, "PDF uncompressed with warnings"
                return False, f"qpdf warnings prevented output: {result.stderr}"
            else:
                return False, f"qpdf error (exit code {result.returncode}): {result.stderr}"
        except subprocess.TimeoutExpired:
            return False, "qpdf timeout - file may be too large or corrupted"
        except FileNotFoundError:
            return False, "qpdf not found - please install qpdf"
        except Exception as e:
            return False, f"Unexpected error during uncompression: {str(e)}"

    def detect_invisible_text(self, pdf_content: str) -> List[Dict[str, any]]:
        """Detect invisible or hidden text in PDF content.

        Uses O(n) two-pass BT/ET scan instead of re.DOTALL regexes
        to avoid catastrophic backtracking on large PDFs.  Falls back
        to decompressed page streams for FlateDecode-compressed PDFs.
        """
        pdf_path = getattr(self, '_current_pdf_path', '') or ''
        return _fast_detect_invisible_text(pdf_content, pdf_path=pdf_path)

    def _extract_text_from_object(self, text_object: str) -> str:
        """Extract readable text from PDF text object."""
        text_pattern = re.compile(r'\((.*?)\)\s*Tj', re.DOTALL)
        texts = text_pattern.findall(text_object)

        array_pattern = re.compile(r'\[(.*?)\]\s*TJ', re.DOTALL)
        arrays = array_pattern.findall(text_object)

        all_text = list(texts)
        for array in arrays:
            strings = re.findall(r'\((.*?)\)', array)
            all_text.extend(strings)

        return ' '.join(all_text).strip()

    def detect_structural_risks(self, file_path: str) -> Dict[str, any]:
        """Detect structural risks in PDF using pdfid."""
        try:
            from pdfid.pdfid import PDFiD, cPDFiD

            xmlDoc = PDFiD(file_path)
            pdfid_obj = cPDFiD(xmlDoc, force=True)

            if pdfid_obj.errorOccured:
                return {
                    'error': f'pdfid error: {pdfid_obj.errorMessage or "unknown error"}',
                    '/JS': 0, '/JavaScript': 0, '/AA': 0, '/OpenAction': 0
                }

            return {
                '/JS': pdfid_obj.js.count,
                '/JavaScript': pdfid_obj.javascript.count,
                '/AA': pdfid_obj.aa.count,
                '/OpenAction': pdfid_obj.openaction.count,
            }

        except ImportError:
            return {'error': 'pdfid not found - install pdfid', '/JS': 0, '/JavaScript': 0, '/AA': 0, '/OpenAction': 0}
        except SystemExit:
            return {'error': 'pdfid error: could not open file', '/JS': 0, '/JavaScript': 0, '/AA': 0, '/OpenAction': 0}
        except Exception as e:
            return {'error': f'pdfid error: {str(e)}', '/JS': 0, '/JavaScript': 0, '/AA': 0, '/OpenAction': 0}

    # Human-readable descriptions for YARA rules
    YARA_RULE_DESCRIPTIONS = {
        'SuspiciousKeywords': (
            'Suspicious keywords commonly used in prompt injection attacks were found in the PDF text. '
            'These phrases may attempt to manipulate AI/LLM systems that process this document.'
        ),
        'HiddenCommands': (
            'Hidden commands or script references were found in the PDF structure. '
            'These elements can execute code automatically when the document is opened, '
            'posing a security risk to the reader.'
        ),
        'EncodedContent': (
            'Multiple encoding or obfuscation methods were detected in the PDF. '
            'While some encoding is normal, the combination found may indicate an attempt '
            'to hide malicious content from security scanners.'
        ),
    }

    YARA_STRING_DESCRIPTIONS = {
        '$prompt1': 'Prompt injection phrase',
        '$prompt2': 'Prompt injection phrase',
        '$prompt3': 'Instruction override keyword',
        '$prompt4': 'Instruction override phrase',
        '$prompt5': 'Instruction injection phrase',
        '$prompt6': 'System prompt reference',
        '$prompt7': 'Role reassignment phrase',
        '$prompt8': 'Role reassignment phrase',
        '$prompt9': 'Impersonation phrase',
        '$prompt10': 'Roleplay keyword',
        '$llm1': 'AI/LLM reference',
        '$llm2': 'AI/LLM reference',
        '$llm3': 'AI/LLM reference',
        '$llm4': 'AI/LLM reference',
        '$llm5': 'Conversation role marker',
        '$llm6': 'Conversation role marker',
        '$exfil1': 'Potential data exfiltration command',
        '$exfil2': 'Potential data exfiltration command',
        '$exfil3': 'Potential data exfiltration command',
        '$exfil4': 'Command-line tool reference',
        '$exfil5': 'Command-line tool reference',
        '$override1': 'Instruction override keyword',
        '$override2': 'Security bypass keyword',
        '$override3': 'Safety disable keyword',
        '$override4': 'Safety disable phrase',
        '$script1': 'JavaScript action reference',
        '$script2': 'JavaScript code reference',
        '$script3': 'Auto-execute on open reference',
        '$script4': 'Additional auto-action reference',
        '$script5': 'External launch reference',
        '$script6': 'Form submission reference',
        '$script7': 'Data import reference',
        '$encode1': 'Hex encoding filter',
        '$encode2': 'ASCII85 encoding filter',
        '$encode3': 'LZW compression filter',
        '$encode4': 'Flate compression filter',
        '$encode5': 'Run-length encoding filter',
        '$encode6': 'Fax encoding filter',
        '$encode7': 'JBIG2 encoding filter',
        '$encode8': 'DCT (JPEG) encoding filter',
    }

    def scan_with_yara(self, content: str) -> List[Dict[str, any]]:
        """Scan content with YARA rules."""
        if self.yara_rules is None:
            return []

        matches = []
        try:
            yara_matches = self.yara_rules.match(data=content)

            for match in yara_matches:
                match_info = {
                    'rule': match.rule,
                    'description': self.YARA_RULE_DESCRIPTIONS.get(
                        match.rule,
                        match.meta.get('description', f'YARA rule "{match.rule}" matched')
                    ),
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }

                for string_match in match.strings:
                    for instance in string_match.instances:
                        matched_text = instance.matched_data.decode('utf-8', errors='ignore')
                        match_info['strings'].append({
                            'offset': instance.offset,
                            'identifier': string_match.identifier,
                            'data': matched_text,
                            'explanation': (
                                f'{self.YARA_STRING_DESCRIPTIONS.get(string_match.identifier, "Pattern match")}'
                                f' — the text "{matched_text}" was found in the PDF'
                            ),
                        })

                matches.append(match_info)

        except Exception as e:
            print(f"YARA scanning error: {e}")

        return matches

    def detect_pii(self, text: str) -> Dict[str, int]:
        """Detect PII using Presidio."""
        if len(text) > 100000:
            text = text[:100000]

        if not text or len(text.strip()) < 10:
            return {'EMAIL_ADDRESS': 0, 'PHONE_NUMBER': 0, 'PERSON': 0}

        try:
            if self.pii_analyzer is None:
                self.pii_analyzer = AnalyzerEngine()

            results = self.pii_analyzer.analyze(
                text=text, language='en',
                entities=['EMAIL_ADDRESS', 'PHONE_NUMBER', 'PERSON']
            )

            pii_counts = {'EMAIL_ADDRESS': 0, 'PHONE_NUMBER': 0, 'PERSON': 0}
            for result in results:
                if result.entity_type in pii_counts:
                    pii_counts[result.entity_type] += 1

            return pii_counts

        except Exception as e:
            print(f"PII detection error: {e}")
            return {'EMAIL_ADDRESS': 0, 'PHONE_NUMBER': 0, 'PERSON': 0}

    def detect_semantic_injection(self, text: str, threshold: float = 0.7) -> List[Dict[str, any]]:
        """Detect potential prompt injection using semantic similarity."""
        if not text or len(text.strip()) < 10:
            return []

        self.load_embedding_model()

        if not self.embedding_available:
            return []

        detections = []
        chunks = self._normalize_and_chunk(text, window_size=500, overlap=100)

        if not chunks:
            return []

        chunk_embeddings = self.embedding_model.encode(chunks)
        pattern_embeddings = self.embedding_model.encode(self.malicious_patterns)

        for i, chunk_emb in enumerate(chunk_embeddings):
            for j, pattern_emb in enumerate(pattern_embeddings):
                similarity = self._cosine_similarity(chunk_emb, pattern_emb)
                if similarity >= threshold:
                    matched = self.malicious_patterns[j]
                    detections.append({
                        'sentence': chunks[i],
                        'matched_pattern': matched,
                        'category': self._pattern_categories.get(matched, "unknown"),
                        'similarity': float(similarity),
                        'index': i
                    })

        return detections

    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors."""
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot_product / (norm1 * norm2)

    def detect_image_anomalies(self, pdf_path: str) -> List[Dict[str, any]]:
        """Detect image anomalies using Shannon entropy for steganography detection."""
        import math
        from collections import Counter

        detections = []

        try:
            import PyPDF2

            with open(pdf_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)

                for page_num in range(len(pdf_reader.pages)):
                    page = pdf_reader.pages[page_num]

                    # Resolve /Resources — may be an IndirectObject
                    resources = page.get('/Resources')
                    if resources is None:
                        continue
                    if hasattr(resources, 'get_object'):
                        resources = resources.get_object()

                    if '/XObject' not in resources:
                        continue

                    # Resolve /XObject dict — may also be indirect
                    xobjects = resources['/XObject']
                    if hasattr(xobjects, 'get_object'):
                        xobjects = xobjects.get_object()

                    for obj_name in xobjects:
                        # Each entry may itself be an IndirectObject
                        obj = xobjects[obj_name]
                        if hasattr(obj, 'get_object'):
                            obj = obj.get_object()

                        if obj.get('/Subtype') == '/Image':
                            try:
                                image_data = obj.get_data()

                                if len(image_data) > 0:
                                    counter = Counter(image_data)
                                    data_len = len(image_data)

                                    entropy = 0.0
                                    for count in counter.values():
                                        p = count / data_len
                                        if p > 0:
                                            entropy -= p * math.log2(p)

                                    if entropy > 7.8:
                                        size_kb = len(image_data) / 1024
                                        detections.append({
                                            'page': page_num + 1,
                                            'object_name': obj_name,
                                            'entropy': round(entropy, 3),
                                            'size_bytes': len(image_data),
                                            'risk': 'potential_steganography_or_malware',
                                            'description': (
                                                f'Suspicious image on page {page_num + 1} '
                                                f'({size_kb:.1f} KB, entropy: {entropy:.3f}). '
                                                f'The image has unusually high data entropy (above 7.8 out of 8.0), '
                                                f'which may indicate hidden data embedded within the image '
                                                f'(steganography) or concealed malicious content.'
                                            ),
                                        })
                            except Exception:
                                continue

        except Exception as e:
            print(f"Image anomaly detection error: {e}")

        return detections

    def detect_citation_spam(self, text: str) -> Dict[str, any]:
        """Detect citation stuffing and SEO spam in text."""
        from urllib.parse import urlparse

        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        urls = url_pattern.findall(text)

        from pdf_sentinel.crossref import extract_dois
        dois = extract_dois(text)

        unique_domains = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    unique_domains.add(parsed.netloc)
            except Exception:
                continue

        text_length = len(text)
        url_count = len(urls)
        doi_count = len(dois)
        domain_count = len(unique_domains)
        url_ratio = (url_count / text_length * 1000) if text_length > 0 else 0

        is_spam = False
        spam_indicators = []

        if url_ratio > 10:
            is_spam = True
            spam_indicators.append(f"High URL density: {url_ratio:.2f} URLs per 1000 chars")

        if domain_count > 20:
            is_spam = True
            spam_indicators.append(f"Excessive domains: {domain_count} unique domains")

        if urls and unique_domains:
            avg_urls_per_domain = url_count / domain_count
            if avg_urls_per_domain > 5:
                is_spam = True
                spam_indicators.append(f"Link farming pattern: {avg_urls_per_domain:.1f} URLs per domain")

        # CrossRef DOI verification (opt-in, requires network)
        crossref_results = {}
        if self.enable_crossref and dois:
            try:
                from pdf_sentinel.crossref import verify_dois, analyze_citation_patterns
                verification = verify_dois(dois)
                crossref_results = analyze_citation_patterns(verification)

                # Promote CrossRef indicators to spam detection
                for ind in crossref_results.get("indicators", []):
                    is_spam = True
                    spam_indicators.append(f"[CrossRef] {ind['description']}")
            except Exception as e:
                crossref_results = {"error": str(e)}

        return {
            'is_spam': is_spam,
            'url_count': url_count,
            'doi_count': doi_count,
            'unique_domains': domain_count,
            'url_ratio_per_1000_chars': round(url_ratio, 2),
            'spam_indicators': spam_indicators,
            'crossref': crossref_results,
        }

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------

    @staticmethod
    def validate_pdf(pdf_path: str, max_size: int = None) -> Tuple[bool, str]:
        """
        Validate that a file is a real PDF within size limits.

        Args:
            pdf_path: Path to the file
            max_size: Maximum allowed size in bytes (default: MAX_FILE_SIZE)

        Returns:
            Tuple of (is_valid, reason)
        """
        if max_size is None:
            max_size = PDFAnalyzer.MAX_FILE_SIZE

        file_size = os.path.getsize(pdf_path)
        if file_size > max_size:
            return False, f"File size {file_size / (1024*1024):.1f} MB exceeds {max_size / (1024*1024):.0f} MB limit"

        # MIME type validation via python-magic
        try:
            import magic
            mime = magic.from_file(pdf_path, mime=True)
            if mime != "application/pdf":
                return False, f"File MIME type is '{mime}', expected 'application/pdf'"
        except ImportError:
            # python-magic not installed — fall back to header check
            pass
        except Exception:
            # libmagic unavailable — fall back to header check
            pass

        # PDF header check (always runs as a fallback / second layer)
        try:
            with open(pdf_path, 'rb') as f:
                header = f.read(8)
            if not header.startswith(b'%PDF'):
                return False, "File does not start with %PDF header — not a valid PDF"
        except OSError as e:
            return False, f"Cannot read file: {e}"

        return True, "OK"

    def analyze_pdf(self, pdf_path: str) -> Dict[str, any]:
        """Perform complete forensic analysis on a PDF file."""
        results = {
            'file_path': pdf_path,
            'file_size': os.path.getsize(pdf_path),
            'uncompressed': False,
            'invisible_text': [],
            'yara_matches': [],
            'semantic_detections': [],
            'structural_risks': {},
            'pii_detections': {},
            'obfuscated_payloads': [],
            'image_anomalies': [],
            'citation_spam': {},
            'errors': []
        }

        # Validate file before proceeding
        is_valid, reason = self.validate_pdf(pdf_path)
        if not is_valid:
            results['errors'].append(f"File rejected: {reason}")
            return results

        self._current_pdf_path = str(pdf_path)
        try:
            # Plugin context dict shared across stages
            ctx = {"pdf_path": pdf_path, "results": results}

            # --- pre_analysis plugins ---
            self._run_plugins("pre_analysis", ctx, results)

            # Structural risk detection
            results['structural_risks'] = self.detect_structural_risks(pdf_path)

            # Image anomaly detection (steganography)
            results['image_anomalies'] = self.detect_image_anomalies(pdf_path)

            temp_dir = None
            try:
                temp_dir = tempfile.mkdtemp(prefix='pdf_sentinel_')
                uncompressed_path = os.path.join(temp_dir, 'uncompressed.pdf')
                success, message = self.uncompress_pdf(pdf_path, uncompressed_path)

                if not success:
                    results['errors'].append(
                        "PDF preparation failed: The PDF file could not be decompressed for analysis. "
                        f"Reason: {message}. Some detection checks may be incomplete."
                    )
                    return results

                results['uncompressed'] = True

                with open(uncompressed_path, 'rb') as f:
                    pdf_bytes = f.read()
                    pdf_content = pdf_bytes.decode('latin-1', errors='ignore')

                ctx["pdf_content"] = pdf_content

                # --- post_decompress plugins ---
                self._run_plugins("post_decompress", ctx, results)

                # Detect invisible text
                results['invisible_text'] = self.detect_invisible_text(pdf_content)

                # YARA scanning
                results['yara_matches'] = self.scan_with_yara(pdf_content)

                # Extract all text for downstream detectors
                all_text = pdf_content
                for inv_text in results['invisible_text']:
                    if inv_text.get('content'):
                        all_text += "\n" + inv_text['content']

                ctx["text"] = all_text

                # --- post_extract plugins ---
                self._run_plugins("post_extract", ctx, results)

                # PII detection
                results['pii_detections'] = self.detect_pii(all_text)

                # Obfuscation detection
                results['obfuscated_payloads'] = self.detect_obfuscated_payloads(all_text)

                # Citation spam detection
                results['citation_spam'] = self.detect_citation_spam(all_text)

                # Semantic injection detection
                if self.enable_semantic:
                    results['semantic_detections'] = self.detect_semantic_injection(all_text)
                else:
                    results['semantic_detections'] = []

                # --- post_analysis plugins ---
                self._run_plugins("post_analysis", ctx, results)

            except Exception as e:
                results['errors'].append(
                    "An unexpected error occurred during PDF analysis. "
                    f"Details: {str(e)}. "
                    "The file may be corrupted or use an unsupported format."
                )
            finally:
                if temp_dir and os.path.exists(temp_dir):
                    try:
                        shutil.rmtree(temp_dir)
                    except Exception as e:
                        results['errors'].append(
                            f"Could not remove temporary files: {str(e)}. "
                            "This does not affect the analysis results."
                        )

            return results
        finally:
            self._current_pdf_path = ""

    def get_risk_score(self, results: Dict[str, any]) -> Tuple[str, int, List[Dict]]:
        """Calculate risk score based on analysis results.
        
        Returns:
            Tuple of (risk_level, score, breakdown) where breakdown is a list of dicts
            with keys: 'factor', 'points', 'detail'
        """
        score = 0
        breakdown = []

        structural_risks = results.get('structural_risks', {})
        has_critical_structural_risk = False

        # Check for /JS or /JavaScript
        js_count = structural_risks.get('/JS', 0)
        javascript_count = structural_risks.get('/JavaScript', 0)
        if js_count > 0 or javascript_count > 0:
            points = 50
            score += points
            has_critical_structural_risk = True
            breakdown.append({
                'factor': '/JS or /JavaScript structural risk',
                'points': points,
                'detail': f'{js_count} /JS tag(s), {javascript_count} /JavaScript tag(s) found'
            })

        # Check for /AA
        aa_count = structural_risks.get('/AA', 0)
        if aa_count > 0:
            points = 30
            score += points
            has_critical_structural_risk = True
            breakdown.append({
                'factor': '/AA (Additional Actions) structural risk',
                'points': points,
                'detail': f'{aa_count} /AA tag(s) found'
            })

        # Check for /OpenAction
        openaction_count = structural_risks.get('/OpenAction', 0)
        if openaction_count > 0:
            points = 30
            score += points
            has_critical_structural_risk = True
            breakdown.append({
                'factor': '/OpenAction structural risk',
                'points': points,
                'detail': f'{openaction_count} /OpenAction tag(s) found'
            })

        # Invisible text
        invisible_count = len(results.get('invisible_text', []))
        if invisible_count > 0:
            points = invisible_count * 20
            score += points
            breakdown.append({
                'factor': 'Invisible text detection',
                'points': points,
                'detail': f'{invisible_count} instance(s) × 20 pts each'
            })

        # YARA matches
        for match in results.get('yara_matches', []):
            if match['rule'] == 'SuspiciousKeywords':
                string_count = len(match.get('strings', []))
                points = string_count * 15
                score += points
                breakdown.append({
                    'factor': f'YARA: {match["rule"]}',
                    'points': points,
                    'detail': f'{string_count} string match(es) × 15 pts each'
                })
            elif match['rule'] == 'HiddenCommands':
                string_count = len(match.get('strings', []))
                points = string_count * 25
                score += points
                breakdown.append({
                    'factor': f'YARA: {match["rule"]}',
                    'points': points,
                    'detail': f'{string_count} string match(es) × 25 pts each'
                })
            elif match['rule'] == 'EncodedContent':
                points = 10
                score += points
                breakdown.append({
                    'factor': f'YARA: {match["rule"]}',
                    'points': points,
                    'detail': 'Encoded content detected'
                })

        # Semantic detections
        semantic_detections = results.get('semantic_detections', [])
        for i, detection in enumerate(semantic_detections, 1):
            similarity = detection.get('similarity', 0)
            if similarity >= 0.9:
                points = 30
            elif similarity >= 0.8:
                points = 20
            else:
                points = 10
            score += points
            breakdown.append({
                'factor': f'Semantic detection #{i}',
                'points': points,
                'detail': f'Similarity: {similarity:.2f}'
            })

        # Determine risk level
        if has_critical_structural_risk:
            if score >= 80:
                risk_level = "CRITICAL"
            else:
                risk_level = "HIGH"
        elif score >= 80:
            risk_level = "CRITICAL"
        elif score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
        elif score > 0:
            risk_level = "LOW"
        else:
            risk_level = "CLEAN"

        return risk_level, min(score, 100), breakdown
