---
title: PDF Sentinel Sandbox
emoji: 🛡️
colorFrom: blue
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
license: mit
---

# PDF Sentinel 🔍

**Advanced PDF Security Scanner** - Detect prompt injection, PII leaks, and malicious PDF structures

[![Security](https://img.shields.io/badge/security-hardened-green.svg)](https://github.com/dblcpm/pdf-sentinel-sandbox)
[![Python](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [Plugin System](#-plugin-system)
- [Security](#-security)
- [Known Issues](#-known-issues)
- [API Reference](#-api-reference)
- [Development](#-development)
- [Troubleshooting](#-troubleshooting)
- [Future Roadmap](#-future-roadmap-dynamic-analysis)
- [Changelog](#-changelog)
- [Contributing](#-contributing)

---

## 🎯 Overview

PDF Sentinel is a comprehensive forensic PDF analysis tool designed for journal editors, security teams, and content moderators to detect sophisticated attacks and privacy violations in PDF documents.

### What It Detects

- 🔍 **Invisible Text**: Hidden content using white-on-white rendering or invisible modes
- 🎯 **Suspicious Keywords**: YARA-based pattern matching for prompt injection
- 🧠 **Semantic Injection**: ML-powered detection of malicious instructions using embeddings
- 🔒 **Privacy Leaks**: PII detection (emails, phone numbers, names)
- ⚠️ **Structural Risks**: JavaScript, auto-actions, and automatic execution vectors
- 🛡️ **Hidden Commands**: Launch actions and other malicious PDF features
- 🔐 **Obfuscated Payloads**: Base64-encoded malicious content detection
- 🖼️ **Image Forensics**: Steganography detection via Shannon entropy analysis
- 📊 **Citation Spam**: Link farming and SEO spam detection in academic documents
- 🔗 **CrossRef DOI Verification**: Validates cited DOIs against the CrossRef API to detect fabricated references, retracted papers, and citation rings

### Key Capabilities

- **Multi-layered Analysis**: Combines pattern matching, semantic analysis, and structural inspection
- **Privacy Scanning**: Detects and counts PII using Microsoft Presidio
- **Homoglyph Defense**: NFKC Unicode normalization defeats character substitution attacks
- **Production Ready**: Non-root Docker execution with pre-baked ML models
- **Risk Scoring**: Intelligent scoring with /JS detection triggering HIGH/CRITICAL alerts
- **CPU Optimized**: Forced CPU execution with thread limiting for deployment on limited hardware
- **Medical Journal Forensics**: Citation spam, DOI verification, and image steganography detection
- **Plugin System**: Extensible architecture for custom detectors via `PluginRegistry`

---

## ✨ Features

### Core Detection Features

- 🔍 **Invisible Text Detection**
  - White RGB color manipulation (`1 1 1 rg`)
  - White grayscale (`1 g`)
  - Invisible rendering mode (`3 Tr`)

- 🎯 **YARA Pattern Matching**
  - Suspicious keyword detection
  - Hidden command identification
  - Encoding/obfuscation analysis

- 🧠 **Advanced Semantic Analysis**
  - Chunk-based embeddings (500 chars with 100 char overlap)
  - Cross-sentence boundary detection
  - Similarity threshold: 0.7 (configurable)

- 🔒 **Privacy Protection**
  - Email address detection
  - Phone number identification
  - Person name recognition
  - 100k character safety limit

- ⚠️ **Structural Risk Analysis**
  - `/JS` - JavaScript code detection
  - `/JavaScript` - JavaScript actions
  - `/AA` - Auto-execute actions
  - `/OpenAction` - Document open triggers

- 🔐 **Obfuscation Detection**
  - Base64-encoded payload detection
  - Automatic decoding and recursive scanning
  - Integration with semantic and YARA detection
  - Minimum 20-character alphanumeric sequences

- 🖼️ **Image Forensics**
  - Shannon entropy calculation for images
  - Steganography detection (entropy > 7.8)
  - Extracts images from PDF streams via PyPDF2
  - Flags potential hidden data/malware containers

- 📊 **Citation Spam Detection**
  - URL and DOI extraction using regex
  - Link farming pattern detection (>5 URLs/domain)
  - Excessive cross-linking detection (>20 unique domains)
  - URL density analysis (URLs per 1000 characters)

- 🔗 **CrossRef DOI Verification** (opt-in)
  - Validates DOIs against the CrossRef public API (no API key required)
  - Detects fabricated (non-resolving) DOIs
  - Identifies retracted papers being cited
  - Flags journal concentration (citation ring patterns)
  - Detects author self-citation clusters
  - Caps lookups at 20 DOIs per scan for performance

### Security Features

- 🐳 **Hardened Deployment**: Non-root user execution (appuser UID 1000)
- 🚀 **Performance**: Pre-downloaded ML models baked into container
- 🛡️ **DoS Prevention**: Character limits and timeout handling
- 🔐 **Secure Processing**: Isolated temp directories with automatic cleanup
- 📊 **Risk Intelligence**: Structural risks force HIGH/CRITICAL escalation
- 🖥️ **CPU Optimized**: Thread limiting (default 2 threads) and forced CPU execution for limited hardware
- 🔒 **Resource Limits**: Configurable CPU (2.0) and memory (4G) limits in docker-compose
- 📁 **Read-Only Filesystem**: Secure tmpfs mounts for /tmp (2G) and cache (1G)
- 🌐 **Network Security**: Localhost-only port binding (127.0.0.1:8501)
- 🤖 **Automated Scanning**: CI/CD vulnerability scanning with pip-audit

---

## 🚀 Installation

### Using Docker (Recommended)

```bash
# Build and run with docker-compose
docker-compose up --build

# Access at http://localhost:8501
```

**Or build manually:**

```bash
docker build -t pdf-sentinel .
docker run -p 8501:7860 pdf-sentinel
```

> **Note:** The Dockerfile exposes port **7860** (Hugging Face Spaces convention). Docker Compose maps it to **8501** for local development.

### Local Installation

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get install qpdf libimage-exiftool-perl libyara-dev gcc g++ \
  poppler-utils binutils

# Install Python dependencies
pip install -r requirements.in

# Download spacy model
python -m spacy download en_core_web_sm

# Run the application
streamlit run app.py
```

### Install as a Python Package

PDF Sentinel can also be installed as a library via `pyproject.toml`:

```bash
pip install .            # core library only
pip install '.[app]'     # includes Streamlit + protobuf for the web UI
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_SEMANTIC_DETECTION` | `true` | Enable/disable ML-based semantic analysis |
| `MAX_CPU_THREADS` | `2` | PyTorch thread limit for CPU execution |
| `CPU_LIMIT` | `2.0` | Docker CPU limit (cores) |
| `MEMORY_LIMIT` | `4G` | Docker memory limit |

```bash
export ENABLE_SEMANTIC_DETECTION=true
streamlit run app.py
```

---

## 📖 Usage

### Web Interface

1. **Upload PDF**: Click "Choose a PDF file to analyze" or drag and drop
2. **Configure Settings**: Adjust semantic detection threshold (0.5-0.95), toggle CrossRef DOI verification
3. **Analyze**: Click "🔍 Analyze PDF" button
4. **Review Results**: Explore findings across six tabs:
   - 🔍 **Invisible Text**: Hidden content detection
   - 🎯 **YARA Matches**: Pattern-based findings
   - 🧠 **Semantic Detection**: ML-powered injection detection
   - 🔒 **Privacy**: PII counts and structural risks
   - ⚠️ **Advanced Threats**: Image anomalies, obfuscated payloads, citation spam, and CrossRef verification
   - 📋 **Summary**: Overall risk assessment with recommendations

### Programmatic Usage

```python
from pdf_sentinel import PDFAnalyzer

# Initialize analyzer
analyzer = PDFAnalyzer('signatures.yara', enable_semantic=True)

# Analyze a PDF file
results = analyzer.analyze_pdf('/path/to/file.pdf')

# Access detection results
print(f"PII Detections: {results['pii_detections']}")
# Output: {'EMAIL_ADDRESS': 5, 'PHONE_NUMBER': 2, 'PERSON': 8}

print(f"Structural Risks: {results['structural_risks']}")
# Output: {'/JS': 3, '/JavaScript': 1, '/AA': 0, '/OpenAction': 1}

print(f"Image Anomalies: {len(results['image_anomalies'])}")
print(f"Obfuscated Payloads: {len(results['obfuscated_payloads'])}")
print(f"Citation Spam: {results['citation_spam']['is_spam']}")

# Get risk assessment
risk_level, risk_score = analyzer.get_risk_score(results)
print(f"Risk Level: {risk_level}")  # HIGH or CRITICAL if /JS detected
print(f"Risk Score: {risk_score}/100")
```

> **Backward compatibility:** `from analyzer import PDFAnalyzer` still works via the shim in the root `analyzer.py`.

### CrossRef DOI Verification

Enable CrossRef verification to validate cited references in academic PDFs:

```python
analyzer = PDFAnalyzer(
    'signatures.yara',
    enable_semantic=True,
    enable_crossref=True,   # opt-in, requires network access
)
results = analyzer.analyze_pdf('/path/to/paper.pdf')

crossref = results['citation_spam'].get('crossref', {})
print(f"Valid DOIs: {crossref.get('valid_count', 0)}")
print(f"Invalid DOIs: {crossref.get('invalid_count', 0)}")
print(f"Retracted: {crossref.get('retracted_count', 0)}")
```

### Risk Level Interpretation

| Level | Score | Description |
|-------|-------|-------------|
| **CLEAN** | 0 | No threats detected |
| **LOW** | 1-24 | Minor concerns, likely safe |
| **MEDIUM** | 25-49 | Several suspicious patterns |
| **HIGH** | 50-79 | Significant threats detected |
| **CRITICAL** | 80-100 | Multiple severe threats |

**Note**: Structural risks (`/JS`, `/JavaScript`) automatically trigger **HIGH** or **CRITICAL** regardless of score.

### Detection Types

1. **Invisible Text**: Text rendered invisible through white RGB color (`1 1 1 rg`), white grayscale (`1 g`), or invisible rendering mode (`3 Tr`).
2. **YARA Matches**: Pattern-based detection of prompt injection keywords, hidden JavaScript/commands, and excessive encoding.
3. **Semantic Detection**: ML-based similarity analysis for instruction override attempts, data exfiltration patterns, and role manipulation.
4. **Obfuscated Payloads**: Base64-encoded content decoded and recursively scanned with semantic and YARA engines.
5. **Image Anomalies**: Shannon entropy analysis flags images with entropy > 7.8 as potential steganography.
6. **Citation Spam**: URL density, domain concentration, and link farming metrics for academic document forensics.

### Docker Deployment

```bash
# Build custom image
docker build -t pdf-sentinel:latest .

# Run container with environment variables
docker run -p 8501:7860 \
  -e ENABLE_SEMANTIC_DETECTION=true \
  -e MAX_CPU_THREADS=2 \
  pdf-sentinel:latest

# Using Docker Compose
docker-compose up -d       # start in background
docker-compose logs -f     # view logs
docker-compose down        # stop
```

---

## 🏗️ Architecture

### Tech Stack

- **Python 3.11** - Core runtime
- **Streamlit** - Web UI framework
- **YARA** - Pattern matching engine
- **Sentence Transformers** - Semantic embeddings (`all-MiniLM-L6-v2`)
- **Presidio** - PII detection engine
- **pdfid** - PDF structural analysis
- **spacy** - NLP processing (`en_core_web_sm`)
- **qpdf** - PDF manipulation tool
- **PyPDF2** - PDF parsing and image extraction
- **CrossRef API** - DOI verification (opt-in)
- **Docker** - Containerization

### Project Structure

```
pdf-sentinel-sandbox/
├── app.py                    # Streamlit web interface
├── analyzer.py               # Backward-compatibility shim
├── pdf_sentinel/             # Core library package
│   ├── __init__.py           # Package exports (PDFAnalyzer, PluginRegistry, crossref)
│   ├── analyzer.py           # Core analysis engine
│   ├── crossref.py           # CrossRef DOI verification module
│   └── plugins.py            # Plugin system (PluginRegistry)
├── signatures.yara           # YARA detection rules
├── pyproject.toml            # Python packaging configuration
├── Dockerfile                # Hardened container config
├── docker-compose.yml        # Orchestration with resource limits
├── requirements.in           # Python dependencies (pip)
├── requirements.txt          # Pinned dependencies
└── .github/workflows/
    ├── security.yml          # pip-audit vulnerability scanning
    └── sync_to_hub.yml       # Hugging Face Spaces deployment
```

### Analysis Pipeline

```
PDF Upload
    ↓
[Plugin: pre_analysis]
    ↓
[1] Structural Analysis (pdfid — /JS, /JavaScript, /AA, /OpenAction)
    ↓
[2] Image Anomaly Detection (Shannon entropy via PyPDF2)
    ↓
[3] PDF Uncompression (qpdf --qdf)
    ↓
[Plugin: post_decompress]
    ↓
[4] Invisible Text Detection (regex patterns)
    ↓
[5] YARA Scanning (signature matching)
    ↓
[6] Text Normalization (NFKC Unicode)
    ↓
[Plugin: post_extract]
    ↓
[7] PII Detection (Presidio, 100k char limit)
    ↓
[8] Obfuscation Detection (Base64 decode + recursive scanning)
    ↓
[9] Citation Spam Detection (URL density, link farming, optional CrossRef)
    ↓
[10] Semantic Analysis (chunk-based embeddings)
    ↓
[Plugin: post_analysis]
    ↓
[11] Risk Scoring (multi-factor assessment)
    ↓
Results Display
```

### Key Algorithms

**1. Text Normalization & Chunking**
```python
def _normalize_and_chunk(text, window_size=500, overlap=100):
    # NFKC normalization defeats homoglyph attacks
    normalized = unicodedata.normalize('NFKC', text)
    
    # Short texts treated as single high-priority chunk
    if len(normalized) < 500:
        return [normalized]

    # Sliding windows preserve context across boundaries
    chunks = []
    start = 0
    while start < len(normalized):
        chunks.append(normalized[start:start + window_size])
        start += window_size - overlap
    return chunks
```

**2. Structural Risk Detection**
- Runs `pdfid` via subprocess (isolated execution)
- Parses output for dangerous tags: `/JS`, `/JavaScript`, `/AA`, `/OpenAction`
- Returns counts with error handling

**3. PII Detection**
- Lazy-loads Presidio AnalyzerEngine (reusable instance)
- 100k character safety limit prevents DoS
- Detects: EMAIL_ADDRESS, PHONE_NUMBER, PERSON

**4. CrossRef DOI Verification**
- Extracts DOIs from text using regex (`10.\d{4,}/...`)
- Queries the free CrossRef API (polite pool, no key required)
- Detects fabricated DOIs, retracted papers, journal concentration, and author self-citation clusters
- Capped at 20 lookups per scan with 10-second timeout per request

---

## 🔌 Plugin System

PDF Sentinel includes an extensible plugin system via `PluginRegistry`. Plugins can inject custom detectors into four pipeline stages.

### Plugin Stages

| Stage | Trigger Point | Context Keys Available |
|-------|--------------|----------------------|
| `pre_analysis` | Before any analysis | `pdf_path` |
| `post_decompress` | After qpdf decompression | `pdf_path`, `pdf_content` |
| `post_extract` | After text extraction | `pdf_path`, `pdf_content`, `text`, partial `results` |
| `post_analysis` | After all built-in detectors | `pdf_path`, `pdf_content`, `text`, full `results` |

### Usage Example

```python
from pdf_sentinel import PDFAnalyzer, PluginRegistry

registry = PluginRegistry()

@registry.detector("watermark_check", stage="post_extract")
def watermark_check(ctx):
    text = ctx.get("text", "")
    if "CONFIDENTIAL" in text.upper():
        return [{"type": "watermark", "description": "Confidential watermark detected"}]
    return []

analyzer = PDFAnalyzer(plugins=registry)
results = analyzer.analyze_pdf("file.pdf")
print(results.get("watermark_check", []))
```

Plugins can also be registered imperatively:

```python
registry.register("my_check", my_function, stage="post_analysis", priority=50)
```

---

## 🔒 Security

### Security Audit Results

**Last Updated**: 2026-01-26
**CodeQL Scan**: ✅ 0 vulnerabilities (Critical: 0, High: 0, Medium: 0, Low: 0)
**Dependency Scan**: ⚠️ 1 known issue (see [Known Issues](#-known-issues))

### Hardening Measures

#### 1. Docker Security
```dockerfile
# Non-root user execution
RUN useradd -m -u 1000 appuser
USER appuser

# Pre-baked models (no runtime downloads)
RUN python -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('all-MiniLM-L6-v2')"
RUN python -m spacy download en_core_web_sm
```

#### 2. DoS Prevention
- File size limits (200MB)
- PII scanning limited to 100k characters
- Timeout on subprocess calls (30s)
- Resource-aware chunking (500 chars)
- CrossRef lookups capped at 20 DOIs per scan

#### 3. Secure File Handling
```python
# Temporary files are created in secure directories
temp_dir = tempfile.mkdtemp(prefix='pdf_sentinel_')

# Automatic cleanup in finally block
try:
    # Process files
    pass
finally:
    shutil.rmtree(temp_dir)
```

#### 4. Input Validation
- PDF file type validation
- Sandboxed processing in temp directories
- No user-controlled file paths
- Subprocess uses list arguments (no shell injection)

#### 5. No Unsafe Operations
- ❌ No `eval()` or `exec()`
- ❌ No `pickle.load()` on untrusted data
- ❌ No `torch.load()` direct usage
- ❌ No SQL injection vectors
- ❌ No command injection (subprocess uses list arguments)

#### 6. Error Handling
- All exceptions properly caught and handled
- No sensitive information in error messages
- Graceful degradation on failures

#### 7. No Hardcoded Secrets
- No API keys in code
- No credentials in configuration
- Environment variables for sensitive config

### Dependency Security

| Package | Version | Status |
|---------|---------|--------|
| torch | ≥2.6.0 | ✅ Patched (CVE fixed) |
| streamlit | ≥1.37.0 | ✅ Secure (PYSEC-2024-153 fixed) |
| protobuf | <7,≥6.33.4 | ⚠️ CVE-2026-0994 (see [Known Issues](#-known-issues)) |
| presidio-analyzer | latest | ✅ Secure |
| pdfid | latest | ✅ Secure |
| spacy | latest | ✅ Secure |
| yara-python | 4.5.0 | ✅ Secure |
| PyPDF2 | 3.0.1 | ✅ Secure |
| sentence-transformers | 2.3.1 | ✅ Secure |
| numpy | 1.26.3 | ✅ Secure |
| python-magic | 0.4.27 | ✅ Secure |

### Threat Model

#### Mitigated Threats

✅ **Malicious PDF Execution**
- PDFs are parsed, not executed
- No JavaScript execution
- No form actions triggered

✅ **Path Traversal**
- All file operations use absolute paths
- Temp directories are randomly generated
- No user-controlled file paths

✅ **Denial of Service**
- File size limits enforced
- Timeout on qpdf operations (30s)
- Resource cleanup guaranteed
- PII scanning capped at 100k characters

✅ **Code Injection**
- No dynamic code execution
- Subprocess arguments use list format (not shell)
- Input sanitization on all user data

✅ **Data Exfiltration**
- No outbound network connections during analysis (except opt-in CrossRef)
- Temporary files automatically deleted
- No logging of sensitive content

#### Residual Risks

⚠️ **Resource Exhaustion** (Low Risk)
- Large PDFs may consume significant memory
- Mitigation: File size limits (200MB) and Docker resource limits
- Recommendation: Deploy with resource limits

⚠️ **Model Poisoning** (Low Risk)
- ML model downloaded from HuggingFace
- Mitigation: Can disable semantic detection
- Recommendation: Use offline model cache in production (pre-baked in Docker)

### Production Deployment Checklist

- [x] Run as non-root user in container
- [x] Pre-download ML models
- [x] Enable resource limits (CPU: 2.0, memory: 4G via docker-compose)
- [x] Use read-only filesystem where possible
- [x] Restrict network access (localhost binding: 127.0.0.1:8501)
- [ ] Enable HTTPS/TLS for web interface
- [x] Set up regular dependency scanning (GitHub Actions with pip-audit)
- [ ] Configure log monitoring
- [x] Document security procedures
- [x] CPU optimization for limited hardware (torch thread limiting, forced CPU execution)
- [x] Secure tmpfs mounts with size limits (/tmp: 2G, /home/appuser/.cache: 1G)

### Current Deployment Status

**CPU-Only Deployment** (Current Configuration):
- ✅ Optimized for deployment on limited CPU hardware (e.g., Hugging Face Spaces)
- ✅ Thread limiting via `MAX_CPU_THREADS` environment variable (default: 2)
- ✅ SentenceTransformer supports configurable device (`device` parameter, default: `'cpu'`)
- ✅ Input validation for thread configuration
- ⚠️ Semantic analysis may be slower without GPU acceleration

**GPU Deployment** (Future Enhancement):
- 🔮 Planned for Q2 2026+ (pending funding)
- 🚀 Will enable faster semantic analysis and dynamic LLM integration
- 📊 Ollama-based quantized models (Llama-3, Mistral) for advanced detection
- ⚡ Expected 10-20x performance improvement for embedding operations

### Yet Unused Tools

The following dependencies are installed but not yet fully utilized:
- **Pillow**: Added for future image processing enhancements (currently using PyPDF2 raw data extraction)
  - Planned use: Advanced image manipulation, format conversion, visual steganography detection
  - Will enable more sophisticated image forensics in future releases

### Recommended Resource Limits

**Current Implementation** (docker-compose.yml):

```yaml
services:
  pdf-sentinel:
    deploy:
      resources:
        limits:
          cpus: '${CPU_LIMIT:-2.0}'
          memory: '${MEMORY_LIMIT:-4G}'
    read_only: true
    tmpfs:
      - /tmp:size=2G
      - /home/appuser/.cache:size=1G
    ports:
      - "127.0.0.1:8501:8501"
    environment:
      - MAX_CPU_THREADS=${MAX_CPU_THREADS:-2}
```

**For CPU-Only Deployments:**
- Minimum: 2 CPU cores, 2GB RAM
- Recommended: 2-4 CPU cores, 4GB RAM
- Large files (>10MB): 4 CPU cores, 8GB RAM

**For GPU Deployments (Future):**
- GPU: NVIDIA GPU with 4GB+ VRAM
- CPU: 4+ cores
- RAM: 8GB+
- Will enable dynamic LLM analysis and faster embeddings

### Security Monitoring

1. **Dependency Updates** — Monitor GitHub Security Advisories; run `pip-audit` regularly; update dependencies monthly.
2. **Log Monitoring** — Monitor for unusual file sizes; track analysis failures; alert on repeated errors.
3. **Resource Monitoring** — Memory usage, disk space (temp directory), CPU utilization.

### Incident Response

- **Report security issues** via [GitHub Security Advisories](https://github.com/dblcpm/pdf-sentinel-sandbox/security/advisories) — do not disclose publicly until patched.
- **Expected response time**: 48 hours.
- **Update procedure**: Pull latest code → Review changelog → Run security scans → Update dependencies → Test in staging → Deploy to production.

### Compliance Notes

- **Data Privacy**: No user data is stored permanently; all uploads are deleted after analysis; no telemetry or tracking.
- **Audit Trail**: Consider enabling access logs for production; log analysis requests (without file content); monitor for abuse patterns.

---

## ⚠️ Known Issues

### CVE-2026-0994: Protobuf JSON Recursion Depth Bypass

**Status**: CANNOT BE FIXED (Dependency Conflict)
**Severity**: Medium
**Affected Package**: protobuf ≤ 6.33.4
**Fixed In**: protobuf ≥ 7.0 (not yet released as stable)

#### Description

The protobuf library has a JSON recursion depth bypass vulnerability (CVE-2026-0994) that affects all versions up to and including 6.33.4.

#### Why This Cannot Be Fixed

- **Fix Requires**: protobuf ≥ 7.0
- **Dependency Conflict**: streamlit (our core dependency) requires protobuf < 7.0
- **Current Version**: We use protobuf 6.33.4 (latest compatible with streamlit)

#### Mitigation

1. **Input Validation**: PDF Sentinel validates and limits input sizes to prevent denial of service attacks.
2. **Monitoring**: We actively monitor for updates to both protobuf and streamlit.
3. **Upgrade Path**: Once streamlit supports protobuf 7.x, we will immediately upgrade.

#### Resolution Timeline

- **Short Term**: No fix available due to dependency conflict.
- **Medium Term**: Waiting for streamlit to support protobuf 7.x (estimated Q2-Q3 2026).
- **Long Term**: Will upgrade immediately when compatible versions are released.

#### Workaround

The vulnerability is temporarily ignored in our CI/CD pipeline (`pip-audit --ignore-vuln CVE-2026-0994`) with full documentation and tracking for future resolution.

#### References

- [CVE-2026-0994](https://nvd.nist.gov/vuln/detail/CVE-2026-0994)
- [Protobuf Releases](https://github.com/protocolbuffers/protobuf/releases)
- [Streamlit Dependencies](https://github.com/streamlit/streamlit)

---

## 📚 API Reference

### PDFAnalyzer Class

```python
class PDFAnalyzer:
    def __init__(
        self,
        yara_rules_path: str = "signatures.yara",
        enable_semantic: bool = True,
        enable_crossref: bool = False,
        device: Optional[str] = None,
        plugins: Optional[PluginRegistry] = None,
    )
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `yara_rules_path` | `str` | `"signatures.yara"` | Path to YARA rules file |
| `enable_semantic` | `bool` | `True` | Enable ML-based semantic detection |
| `enable_crossref` | `bool` | `False` | Verify DOIs via CrossRef API (requires network) |
| `device` | `str \| None` | `None` (→ `"cpu"`) | Torch device for embeddings (`'cpu'`, `'cuda'`, etc.) |
| `plugins` | `PluginRegistry \| None` | `None` | Optional plugin registry with custom detectors |

### Methods

```python
def analyze_pdf(self, pdf_path: str) -> Dict[str, any]
    """Complete forensic analysis of a PDF file"""

def get_risk_score(self, results: Dict[str, any]) -> Tuple[str, int]
    """Calculate risk level and score (0-100)"""

def detect_invisible_text(self, pdf_content: str) -> List[Dict[str, any]]
    """Detect hidden text patterns in decompressed PDF content"""

def scan_with_yara(self, content: str) -> List[Dict[str, any]]
    """Pattern matching with YARA rules"""

def detect_semantic_injection(self, text: str, threshold: float = 0.7) -> List[Dict[str, any]]
    """ML-based injection detection using chunk-based embeddings"""

def detect_structural_risks(self, file_path: str) -> Dict[str, int]
    """Detect dangerous PDF structures using pdfid"""

def detect_pii(self, text: str) -> Dict[str, int]
    """Detect PII using Presidio (100k char limit)"""

def detect_obfuscated_payloads(self, text: str) -> List[Dict[str, any]]
    """Detect Base64-encoded payloads with recursive scanning"""

def detect_image_anomalies(self, pdf_path: str) -> List[Dict[str, any]]
    """Shannon entropy analysis for steganography detection"""

def detect_citation_spam(self, text: str) -> Dict[str, any]
    """Detect citation stuffing, link farming, and optionally verify DOIs"""
```

### Results Dictionary Structure

```python
{
    'file_path': str,
    'file_size': int,
    'uncompressed': bool,
    'invisible_text': List[Dict],
    'yara_matches': List[Dict],
    'semantic_detections': List[Dict],
    'structural_risks': {
        '/JS': int,
        '/JavaScript': int,
        '/AA': int,
        '/OpenAction': int
    },
    'pii_detections': {
        'EMAIL_ADDRESS': int,
        'PHONE_NUMBER': int,
        'PERSON': int
    },
    'obfuscated_payloads': List[Dict],
    'image_anomalies': List[Dict],
    'citation_spam': {
        'is_spam': bool,
        'url_count': int,
        'doi_count': int,
        'unique_domains': int,
        'url_ratio_per_1000_chars': float,
        'spam_indicators': List[str],
        'crossref': Dict   # present when enable_crossref=True
    },
    'errors': List[str]
}
```

### CrossRef Module

```python
from pdf_sentinel.crossref import extract_dois, verify_dois, analyze_citation_patterns

dois = extract_dois(text)                # extract DOIs from text
verification = verify_dois(dois)         # validate against CrossRef API
analysis = analyze_citation_patterns(verification)  # detect suspicious patterns
```

---

## 🛠️ Development

### Customizing YARA Rules

Edit `signatures.yara` to add custom patterns:

```yara
rule CustomPattern {
    meta:
        description = "Detects custom pattern"
        author = "Your Name"
    
    strings:
        $pattern1 = "custom keyword" nocase
        $pattern2 = /regex[0-9]+/
    
    condition:
        any of them
}
```

### Running Tests

```bash
# Install development dependencies
pip install -r requirements.in

# Validate code structure
python -m py_compile app.py pdf_sentinel/analyzer.py pdf_sentinel/crossref.py pdf_sentinel/plugins.py

# Run validation tests
pytest  # (if test suite exists)
```

### Performance Benchmarks

| PDF Size | Analysis Time | Notes |
|----------|--------------|-------|
| < 1MB | 1-3 seconds | Fast |
| 1-10MB | 5-15 seconds | Medium |
| > 10MB | 30+ seconds | Large |

**Semantic Detection**: Adds 5-10 seconds for model loading (first run only, cached thereafter).
**CrossRef Verification**: Adds ~10 seconds per DOI checked (network dependent).

---

## 🔧 Troubleshooting

### Common Issues

#### Model Download Failures
```bash
# Disable semantic detection if needed
export ENABLE_SEMANTIC_DETECTION=false
streamlit run app.py
```

#### qpdf Not Found
```bash
# Ubuntu/Debian
sudo apt-get install qpdf

# macOS
brew install qpdf

# CentOS/RHEL
sudo yum install qpdf
```

#### YARA Errors
```bash
sudo apt-get install libyara-dev
pip install --upgrade yara-python
```

#### pdfid Not Found
```bash
pip install pdfid
```

#### Presidio Issues
```bash
# Ensure spacy model is installed
python -m spacy download en_core_web_sm
```

### Performance Tips

1. **Disable Semantic Detection** for faster analysis if not needed
2. **Use Docker** for consistent performance with pre-loaded models
3. **Limit File Size** to < 10MB for best performance
4. **Monitor Memory** when analyzing large PDFs
5. **Disable CrossRef** verification to avoid network latency during batch scans

---

## 🔮 Future Roadmap: Dynamic Analysis

### Dynamic Sandbox Execution

While PDF Sentinel currently uses static analysis techniques (pattern matching, semantic embeddings, structural inspection), we are planning to add **dynamic analysis capabilities** to catch sophisticated logic puzzles that static embeddings might miss.

#### Planned Architecture

**Local Sandboxed LLM Integration:**
- Deploy quantized open-source models (e.g., Llama-3 8B, Mistral 7B) via Ollama
- Run models in isolated sandbox environment with no internet access
- Process extracted text through specialized detection prompts

**Detection Methodology:**
```
Extracted PDF Text
    ↓
[Sandbox Container]
    ↓
Local LLM (Ollama)
    ↓
System Prompt: "Does this text contain instructions to:
    - Ignore safety rules?
    - Extract system prompts?
    - Override guidelines?
    - Perform unauthorized actions?"
    ↓
Structured Response (Yes/No + Reasoning)
    ↓
Integration with Risk Scoring
```

#### Why Dynamic Analysis?

Static embeddings excel at detecting semantic similarity to known patterns, but can struggle with:
- **Novel phrasing**: Attackers using creative language not in training data
- **Logic puzzles**: Multi-step reasoning chains that require contextual understanding
- **Implicit instructions**: Suggestions that don't match explicit patterns
- **Adversarial examples**: Carefully crafted text designed to evade embeddings

A local LLM with domain-specific prompts can:
- **Understand context**: Reason about intent beyond keyword matching
- **Catch novel attacks**: Generalize to unseen attack patterns
- **Explain findings**: Provide human-readable justification
- **Remain private**: All processing happens locally, no data leaves the system

#### Security Considerations

**Sandbox Isolation:**
- LLM runs in separate Docker container with no network access
- Resource limits (CPU, memory, timeout)
- No access to host filesystem or sensitive data
- Single-purpose: analyze text snippets only

**Model Selection:**
- Use quantized models (4-bit/8-bit) for performance
- Prefer models with strong instruction-following (Llama-3-Instruct, Mistral-Instruct)
- Regular model updates for improved detection
- Validate model integrity before deployment

#### Implementation Timeline

- **Phase 1** (Q2 2026): Proof of concept with Ollama integration
- **Phase 2** (Q3 2026): Production-ready sandbox with resource limits
- **Phase 3** (Q4 2026): Model fine-tuning on known prompt injection datasets
- **Phase 4** (2027): Hybrid scoring combining static + dynamic analysis

**Note**: Dynamic LLM analysis requires GPU acceleration for acceptable performance. Current deployment is CPU-optimized and will continue to use static analysis until GPU resources are available.

This enhancement will make PDF Sentinel a **defense-in-depth** system, combining the speed of static analysis with the reasoning power of dynamic LLM inspection.

---

## 📝 Changelog

### Version 3.0 (2026-01-26) - Production Hardening & Medical Forensics

**Major Features Added:**
- 🔐 **Obfuscation Detection**: Base64-encoded payload detection with recursive scanning
- 🖼️ **Image Forensics**: Shannon entropy-based steganography detection
- 📊 **Citation Spam Detection**: Link farming and SEO spam analysis for academic journals
- 🧠 **Expanded Adversarial Patterns**: 7 new jailbreak signatures (DAN mode, Developer Mode, etc.)
- 🖥️ **CPU Optimization**: Thread limiting and forced CPU execution for limited hardware
- 🔗 **CrossRef DOI Verification**: Opt-in citation integrity checking via CrossRef API
- 🔌 **Plugin System**: Extensible `PluginRegistry` with four pipeline stages
- 📦 **Package Restructure**: Moved core logic into `pdf_sentinel/` package with `pyproject.toml`

**Production Hardening:**
- Resource limits in docker-compose (CPU: 2.0, Memory: 4G)
- Read-only filesystem with secure tmpfs mounts (2G /tmp, 1G cache)
- Localhost-only port binding (127.0.0.1:8501)
- Automated vulnerability scanning via GitHub Actions (pip-audit)
- Input validation for MAX_CPU_THREADS environment variable

**Medical Journal Forensics:**
- Image anomaly detection: Shannon entropy > 7.8 flags potential steganography
- Citation spam metrics: URL density, domain counting, link farming detection
- Obfuscated payload extraction and recursive semantic/YARA scanning
- CrossRef DOI verification: fake DOI detection, retracted paper flagging, citation ring analysis

**Security Improvements:**
- Minimal GITHUB_TOKEN permissions in CI/CD workflows
- tmpfs size limits for DoS protection
- Thread limiting to prevent container lockups on CPU-only hardware
- Comprehensive input validation for environment variables

**Technical Improvements:**
- PyTorch thread limiting via MAX_CPU_THREADS (default: 2)
- SentenceTransformer configurable device parameter (`device='cpu'` default)
- Refined chunking logic: text < 500 chars treated as single high-priority chunk
- Environment variable configuration for resource limits
- Backward-compatible `analyzer.py` shim at project root

**Dependencies Added:**
- Pillow (for future image processing enhancements)
- torch (explicit dependency for CPU optimization)

**Deployment Configuration:**
- Optimized for CPU-only environments (Hugging Face Spaces, standard servers)
- GPU support planned for Q2 2026+ (dynamic LLM analysis)
- Configurable resource limits via environment variables

**Challenges Addressed:**
1. **CPU Performance**: Thread limiting prevents lockups on limited hardware
2. **Medical Journal Attacks**: New forensics detect citation manipulation and hidden images
3. **Obfuscation Evasion**: Recursive Base64 detection catches encoded payloads
4. **Production Security**: Comprehensive hardening for real-world deployment
5. **Resource Management**: Granular control over CPU, memory, and filesystem access

### Version 2.0 (2026-01-26) - Privacy & Structural Analysis

**Major Features Added:**
- 🔒 **PII Detection**: Presidio-based privacy scanning
- ⚠️ **Structural Risk Analysis**: pdfid integration for dangerous PDF elements
- 🛡️ **Enhanced Semantic Detection**: Chunk-based analysis (was sentence-based)
- 🔐 **Hardened Deployment**: Non-root Docker user, pre-baked models

**Security Improvements:**
- DoS prevention with 100k character limit on PII scanning
- Homoglyph defense via NFKC Unicode normalization
- Subprocess isolation for pdfid execution
- /JS detection triggers HIGH/CRITICAL risk levels

**Technical Improvements:**
- Lazy loading for PII analyzer (instance reuse)
- Sliding window chunking (500 chars, 100 overlap)
- Optimized Docker build with pre-downloaded models
- Added poppler-utils and binutils dependencies

**UI Enhancements:**
- New "Privacy" tab showing PII and structural risks
- Color-coded structural risk metrics
- Expanded summary with PII counts
- Enhanced security warnings

**Dependencies Added:**
- presidio-analyzer (PII detection)
- pdfid (structural analysis)
- spacy (NLP support)

**Challenges Addressed:**
1. **Model Loading**: Pre-baked models in Docker to eliminate startup delays
2. **Security Hardening**: Non-root execution prevents privilege escalation
3. **Performance**: Lazy loading and chunking prevent memory issues
4. **Cross-boundary Detection**: Sliding windows catch attacks spanning sentences
5. **Risk Accuracy**: Structural analysis ensures JavaScript triggers appropriate alerts

### Version 1.0 (Initial Release)

- Basic invisible text detection
- YARA pattern matching
- Semantic injection detection
- Docker deployment
- Web UI with Streamlit

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Contribution Guidelines

- Follow PEP 8 style guide
- Add tests for new features
- Update documentation
- Run security scans before submitting
- Keep commits focused and atomic

---

## 📄 License

MIT License - see LICENSE file for details

---

## 🙏 Acknowledgments

- **YARA Project** - Pattern matching engine
- **Sentence Transformers** - Embedding models
- **Microsoft Presidio** - PII detection framework
- **CrossRef** - DOI verification API
- **qpdf & pdfid** - PDF analysis tools
- **Streamlit** - Web UI framework
- **spacy** - NLP library

---

## 📧 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/dblcpm/pdf-sentinel-sandbox/issues)
- **Security**: Report via [GitHub Security Advisories](https://github.com/dblcpm/pdf-sentinel-sandbox/security/advisories)
- **Documentation**: This README
- **Updates**: Watch repository for releases

---

**Last Updated**: 2026-02-07
**Version**: 3.0
**Status**: Production Ready ✅
**Deployment**: CPU-Optimized (GPU support planned Q2 2026+)
