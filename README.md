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

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [Security](#security)
- [API Reference](#api-reference)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)
- [Contributing](#contributing)

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

### Key Capabilities

- **Multi-layered Analysis**: Combines pattern matching, semantic analysis, and structural inspection
- **Privacy Scanning**: Detects and counts PII using Microsoft Presidio
- **Homoglyph Defense**: NFKC Unicode normalization defeats character substitution attacks
- **Production Ready**: Non-root Docker execution with pre-baked ML models
- **Risk Scoring**: Intelligent scoring with /JS detection triggering HIGH/CRITICAL alerts
- **CPU Optimized**: Forced CPU execution with thread limiting for deployment on limited hardware
- **Medical Journal Forensics**: Citation spam and image steganography detection

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

- 🔒 **Privacy Protection (NEW)**
  - Email address detection
  - Phone number identification
  - Person name recognition
  - 100k character safety limit

- ⚠️ **Structural Risk Analysis**
  - `/JS` - JavaScript code detection
  - `/JavaScript` - JavaScript actions
  - `/AA` - Auto-execute actions
  - `/OpenAction` - Document open triggers

- 🔐 **Obfuscation Detection (NEW)**
  - Base64-encoded payload detection
  - Automatic decoding and recursive scanning
  - Integration with semantic and YARA detection
  - Minimum 20-character alphanumeric sequences

- 🖼️ **Image Forensics (NEW)**
  - Shannon entropy calculation for images
  - Steganography detection (entropy > 7.8)
  - Extracts images from PDF streams via PyPDF2
  - Flags potential hidden data/malware containers

- 📊 **Citation Spam Detection (NEW)**
  - URL and DOI extraction using regex
  - Link farming pattern detection (>5 URLs/domain)
  - Excessive cross-linking detection (>20 unique domains)
  - URL density analysis (URLs per 1000 characters)

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
docker run -p 8501:8501 pdf-sentinel
```

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

### Environment Variables

```bash
# Enable/disable semantic detection
export ENABLE_SEMANTIC_DETECTION=true

# Run application
streamlit run app.py
```

---

## 📖 Usage

### Web Interface

1. **Upload PDF**: Click "Choose a PDF file to analyze" or drag and drop
2. **Configure Settings**: Adjust semantic detection threshold (0.5-0.95)
3. **Analyze**: Click "🔍 Analyze PDF" button
4. **Review Results**: Explore findings across multiple tabs:
   - 🔍 **Invisible Text**: Hidden content detection
   - 🎯 **YARA Matches**: Pattern-based findings
   - 🧠 **Semantic Detection**: ML-powered injection detection
   - 🔒 **Privacy**: PII counts and structural risks
   - 📋 **Summary**: Overall risk assessment

### Programmatic Usage

```python
from analyzer import PDFAnalyzer

# Initialize analyzer
analyzer = PDFAnalyzer('signatures.yara', enable_semantic=True)

# Analyze a PDF file
results = analyzer.analyze_pdf('/path/to/file.pdf')

# Access new features
print(f"PII Detections: {results['pii_detections']}")
# Output: {'EMAIL_ADDRESS': 5, 'PHONE_NUMBER': 2, 'PERSON': 8}

print(f"Structural Risks: {results['structural_risks']}")
# Output: {'/JS': 3, '/JavaScript': 1, '/AA': 0, '/OpenAction': 1}

# Get risk assessment
risk_level, risk_score = analyzer.get_risk_score(results)
print(f"Risk Level: {risk_level}")  # HIGH or CRITICAL if /JS detected
print(f"Risk Score: {risk_score}/100")
```

### Risk Level Interpretation

| Level | Score | Description |
|-------|-------|-------------|
| **CLEAN** | 0 | No threats detected |
| **LOW** | 1-24 | Minor concerns, likely safe |
| **MEDIUM** | 25-49 | Several suspicious patterns |
| **HIGH** | 50-79 | Significant threats detected |
| **CRITICAL** | 80-100 | Multiple severe threats |

**Note**: Structural risks (/JS, /JavaScript) automatically trigger **HIGH** or **CRITICAL** regardless of score.

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
- **Docker** - Containerization

### Components

```
pdf-sentinel/
├── app.py              # Streamlit web interface
├── analyzer.py         # Core analysis engine
├── signatures.yara     # YARA detection rules
├── Dockerfile          # Hardened container config
├── docker-compose.yml  # Orchestration
└── requirements.in     # Python dependencies
```

### Analysis Pipeline

```
PDF Upload
    ↓
[1] Structural Analysis (pdfid)
    ↓
[2] PDF Uncompression (qpdf --qdf)
    ↓
[3] Invisible Text Detection (regex patterns)
    ↓
[4] YARA Scanning (signature matching)
    ↓
[5] Text Normalization (NFKC Unicode)
    ↓
[6] PII Detection (Presidio, 100k char limit)
    ↓
[7] Semantic Analysis (chunk-based embeddings)
    ↓
[8] Risk Scoring (multi-factor assessment)
    ↓
Results Display
```

### Key Algorithms

**1. Text Normalization & Chunking**
```python
def _normalize_and_chunk(text, window_size=500, overlap=100):
    # NFKC normalization defeats homoglyph attacks
    normalized = unicodedata.normalize('NFKC', text)
    
    # Sliding windows preserve context across boundaries
    chunks = []
    for start in range(0, len(normalized), window_size - overlap):
        chunks.append(normalized[start:start + window_size])
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

---

## 🔒 Security

### Security Status

**Last Updated**: 2026-01-26  
**CodeQL Scan**: ✅ 0 vulnerabilities  
**Dependency Scan**: ⚠️ 1 known issue (see [KNOWN_ISSUES.md](KNOWN_ISSUES.md))

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

#### 3. Input Validation
- PDF file type validation
- Sandboxed processing in temp directories
- No user-controlled file paths
- Subprocess uses list arguments (no shell injection)

#### 4. No Unsafe Operations
- ❌ No `eval()` or `exec()`
- ❌ No `pickle.load()` on untrusted data
- ❌ No `torch.load()` direct usage
- ❌ No SQL injection vectors

### Dependency Security

| Package | Version | Status |
|---------|---------|--------|
| torch | ≥2.6.0 | ✅ Patched (CVE fixed) |
| streamlit | ≥1.37.0 | ✅ Secure (PYSEC-2024-153 fixed) |
| protobuf | <7,≥6.33.4 | ⚠️ CVE-2026-0994 (see [KNOWN_ISSUES.md](KNOWN_ISSUES.md)) |
| presidio-analyzer | latest | ✅ Secure |
| pdfid | latest | ✅ Secure |
| spacy | latest | ✅ Secure |
| yara-python | 4.5.0 | ✅ Secure |

### Production Deployment Checklist

- [x] Run as non-root user in container
- [x] Pre-download ML models
- [x] Enable resource limits (CPU: 2.0, memory: 4G via docker-compose)
- [x] Use read-only filesystem where possible
- [x] Restrict network access (localhost binding: 127.0.0.1:8501)
- [ ] Enable HTTPS/TLS for web interface
- [x] Set up regular dependency scanning (GitHub Actions with pip-audit)
- [ ] Configure log monitoring
- [x] Document security procedures (see [KNOWN_ISSUES.md](KNOWN_ISSUES.md))
- [x] CPU optimization for limited hardware (torch thread limiting, forced CPU execution)
- [x] Secure tmpfs mounts with size limits (/tmp: 2G, /home/appuser/.cache: 1G)

### Current Deployment Status

**CPU-Only Deployment** (Current Configuration):
- ✅ Optimized for deployment on limited CPU hardware (e.g., Hugging Face Spaces)
- ✅ Thread limiting via `MAX_CPU_THREADS` environment variable (default: 2)
- ✅ SentenceTransformer forced to CPU mode (`device='cpu'`)
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
# docker-compose.yml
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

**Environment Variables:**
- `CPU_LIMIT`: CPU limit (default: 2.0 cores)
- `MEMORY_LIMIT`: Memory limit (default: 4G)
- `MAX_CPU_THREADS`: PyTorch thread limit (default: 2 threads)

**For CPU-Only Deployments:**
- Minimum: 2 CPU cores, 2GB RAM
- Recommended: 2-4 CPU cores, 4GB RAM
- Large files (>10MB): 4 CPU cores, 8GB RAM

**For GPU Deployments (Future):**
- GPU: NVIDIA GPU with 4GB+ VRAM
- CPU: 4+ cores
- RAM: 8GB+
- Will enable dynamic LLM analysis and faster embeddings

---

## 📚 API Reference

### PDFAnalyzer Class

```python
class PDFAnalyzer:
    def __init__(self, yara_rules_path: str = "signatures.yara", 
                 enable_semantic: bool = True)
    
    def _normalize_and_chunk(self, text: str, window_size: int = 500, 
                            overlap: int = 100) -> List[str]
        """Normalize text and split into sliding windows"""
    
    def detect_structural_risks(self, file_path: str) -> Dict[str, int]
        """Detect dangerous PDF structures using pdfid"""
    
    def detect_pii(self, text: str) -> Dict[str, int]
        """Detect PII using Presidio (100k char limit)"""
    
    def detect_invisible_text(self, pdf_content: str) -> List[Dict[str, any]]
        """Detect hidden text patterns"""
    
    def scan_with_yara(self, content: str) -> List[Dict[str, any]]
        """Pattern matching with YARA rules"""
    
    def detect_semantic_injection(self, text: str, threshold: float = 0.7) 
        -> List[Dict[str, any]]
        """ML-based injection detection (chunk-based)"""
    
    def analyze_pdf(self, pdf_path: str) -> Dict[str, any]
        """Complete forensic analysis"""
    
    def get_risk_score(self, results: Dict[str, any]) -> Tuple[str, int]
        """Calculate risk level and score"""
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
    'errors': List[str]
}
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
python -m py_compile analyzer.py app.py

# Run validation tests
pytest  # (if test suite exists)
```

### Performance Benchmarks

| PDF Size | Analysis Time | Notes |
|----------|--------------|-------|
| < 1MB | 1-3 seconds | Fast |
| 1-10MB | 5-15 seconds | Medium |
| > 10MB | 30+ seconds | Large |

**Semantic Detection**: Adds 5-10 seconds for model loading (first run only, cached thereafter)

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

**Security Improvements:**
- Minimal GITHUB_TOKEN permissions in CI/CD workflows
- tmpfs size limits for DoS protection
- Thread limiting to prevent container lockups on CPU-only hardware
- Comprehensive input validation for environment variables

**Technical Improvements:**
- PyTorch thread limiting via MAX_CPU_THREADS (default: 2)
- SentenceTransformer forced to CPU mode (`device='cpu'`)
- Refined chunking logic: text < 500 chars treated as single high-priority chunk
- Environment variable configuration for resource limits

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
- **qpdf & pdfid** - PDF analysis tools
- **Streamlit** - Web UI framework
- **spacy** - NLP library

---

## 📧 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/dblcpm/pdf-sentinel-sandbox/issues)
- **Security**: Report via GitHub Security Advisories
- **Documentation**: This README
- **Updates**: Watch repository for releases

---

**Last Updated**: 2026-01-26  
**Version**: 3.0  
**Status**: Production Ready ✅  
**Deployment**: CPU-Optimized (GPU support planned Q2 2026+)
