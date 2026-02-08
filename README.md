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

**Forensic PDF Security Scanner** — Detect prompt injection, PII leaks, and malicious PDF structures.

[![Python](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **Live Demo (CPU):** Deployed on [Hugging Face Spaces](https://huggingface.co/spaces/dblcpm/pdf-sentinel-sandbox) — upload a PDF and get results in seconds.

---

## Project Status

PDF Sentinel is a **working static-analysis tool** deployed as a CPU-only Docker app.
The table below is an honest snapshot of what is implemented, what is missing, and what is planned.

### ✅ Implemented & Working

| Feature | Details |
|---------|---------|
| Invisible text detection | Three regex patterns: white RGB, white grayscale, invisible render mode |
| YARA pattern matching | Three rule sets: `SuspiciousKeywords`, `HiddenCommands`, `EncodedContent` |
| Semantic injection detection | `all-MiniLM-L6-v2` embeddings, chunk-based (500 char windows, 100 overlap) |
| PII detection | Presidio — EMAIL_ADDRESS, PHONE_NUMBER, PERSON (100 k char cap) |
| Structural risk analysis | `pdfid` — `/JS`, `/JavaScript`, `/AA`, `/OpenAction` counts |
| Base64 obfuscation detection | Decode + recursive YARA & semantic scan |
| Image entropy analysis | Shannon entropy via PyPDF2; flags > 7.8 as potential steganography |
| Citation spam detection | URL density, domain concentration, link-farming heuristics |
| CrossRef DOI verification | Opt-in; validates up to 20 DOIs per scan against CrossRef API |
| Plugin system | `PluginRegistry` with 4 pipeline stages (`pre_analysis` → `post_analysis`) |
| Risk scoring | Multi-factor score 0-100; `/JS` forces HIGH/CRITICAL |
| Streamlit web UI | File upload, 6 result tabs, configurable settings sidebar |
| Docker hardening | Non-root user, pre-baked models, read-only FS, tmpfs, resource limits |
| CPU thread limiting | `MAX_CPU_THREADS` env var (default 2) via PyTorch |
| CI/CD | `pip-audit` security scanning, Hugging Face Spaces sync |

### ⚠️ Documented but Not Implemented

| Gap | Notes |
|-----|-------|
| 200 MB file-size limit | Mentioned in security docs; **not enforced in code** |
| `python-magic` usage | Listed in `requirements.txt` / `pyproject.toml` but **never imported** |
| `Pillow` usage | Installed; **not used** (image analysis uses raw PyPDF2 byte data) |
| Test suite | **No tests exist.** README hedges with "if test suite exists" |
| ~~`LICENSE` file~~ | ~~README references it~~ — **added in this release** |
| HTTPS / TLS | Noted as TODO in deployment checklist |
| Log monitoring | Noted as TODO in deployment checklist |

### 🔮 Future / Not Started

| Item | Target |
|------|--------|
| Dynamic LLM analysis (Ollama sandbox) | Concept only — no code |
| GPU deployment | No GPU-specific code; `device` param defaults to `cpu` |
| Advanced Pillow image forensics | No code |
| Fine-tuned injection detection model | No code |

---

## Quick Start

### Hugging Face Spaces (Recommended)

The app is deployed at <https://huggingface.co/spaces/dblcpm/pdf-sentinel-sandbox>.
Upload a PDF → adjust the semantic threshold → click **Analyze**.

### Docker

```bash
# Build and run
docker build -t pdf-sentinel .
docker run -p 8501:7860 pdf-sentinel

# Or via Compose (localhost-only, resource limits)
docker-compose up --build    # http://localhost:8501
```

### Local

```bash
# System deps (Ubuntu/Debian)
sudo apt-get install qpdf libyara-dev poppler-utils

# Python deps
pip install -r requirements.in
python -m spacy download en_core_web_sm

# Run
streamlit run app.py
```

### As a Library

```bash
pip install .            # core only
pip install '.[app]'     # includes Streamlit UI
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_SEMANTIC_DETECTION` | `true` | Toggle ML semantic analysis |
| `MAX_CPU_THREADS` | `2` | PyTorch thread cap |
| `CPU_LIMIT` | `2.0` | Docker CPU cores |
| `MEMORY_LIMIT` | `4G` | Docker memory cap |

---

## Usage

### Web UI

1. Upload a PDF
2. Adjust settings in the sidebar (semantic threshold, CrossRef toggle)
3. Click **🔍 Analyze PDF**
4. Browse six result tabs: Invisible Text · YARA · Semantic · Privacy · Advanced Threats · Summary

### Python API

```python
from pdf_sentinel import PDFAnalyzer

analyzer = PDFAnalyzer("signatures.yara", enable_semantic=True)
results = analyzer.analyze_pdf("paper.pdf")
risk_level, risk_score = analyzer.get_risk_score(results)

print(risk_level, risk_score)          # e.g. "HIGH", 65
print(results["pii_detections"])       # {'EMAIL_ADDRESS': 2, ...}
print(results["structural_risks"])     # {'/JS': 1, ...}
```

> Backward compat: `from analyzer import PDFAnalyzer` still works via the root shim.

### Risk Levels

| Level | Score | Trigger |
|-------|-------|---------|
| CLEAN | 0 | Nothing found |
| LOW | 1–24 | Minor patterns |
| MEDIUM | 25–49 | Multiple signals |
| HIGH | 50–79 | Serious threats **or** `/JS` · `/JavaScript` present |
| CRITICAL | 80–100 | Many severe findings |

---

## Architecture

```
pdf-sentinel-sandbox/
├── app.py                 # Streamlit UI
├── analyzer.py            # Backward-compat shim
├── pdf_sentinel/
│   ├── __init__.py        # Exports: PDFAnalyzer, PluginRegistry, crossref
│   ├── analyzer.py        # Core analysis engine (11 detection methods)
│   ├── crossref.py        # CrossRef DOI verification
│   └── plugins.py         # PluginRegistry (4 stages)
├── signatures.yara        # YARA rules (3 rules)
├── pyproject.toml         # Package config
├── Dockerfile             # Hardened container (non-root, pre-baked models)
├── docker-compose.yml     # Resource limits, read-only FS, tmpfs
├── requirements.in        # Human-readable deps
└── requirements.txt       # Pinned deps
```

**Pipeline:** Upload → `pre_analysis` plugins → structural analysis → image entropy → qpdf decompress → `post_decompress` plugins → invisible text → YARA → normalize/chunk → `post_extract` plugins → PII → base64 → citation spam → semantic → `post_analysis` plugins → risk scoring → display.

---

## Plugin System

```python
from pdf_sentinel import PDFAnalyzer, PluginRegistry

registry = PluginRegistry()

@registry.detector("watermark_check", stage="post_extract")
def watermark_check(ctx):
    if "CONFIDENTIAL" in ctx.get("text", "").upper():
        return [{"type": "watermark", "description": "Confidential watermark found"}]
    return []

analyzer = PDFAnalyzer(plugins=registry)
results = analyzer.analyze_pdf("file.pdf")
```

Stages: `pre_analysis` · `post_decompress` · `post_extract` · `post_analysis`.

---

## Security

**Hardening:** non-root Docker user · pre-baked models · read-only FS · tmpfs size caps · localhost-only binding · subprocess list args (no shell) · no `eval`/`exec`/`pickle` · 100 k PII char limit · 30 s subprocess timeout.

**Known issue — CVE-2026-0994 (protobuf ≤ 6.33.4):**
Streamlit requires `protobuf < 7` so we are pinned to 6.33.4. Mitigated by input-size limits. Will upgrade when Streamlit supports protobuf 7.x.

Report vulnerabilities via [GitHub Security Advisories](https://github.com/dblcpm/pdf-sentinel-sandbox/security/advisories).

---

## Roadmap

Short-term (next release):
- [ ] Add automated test suite (pytest)
- [ ] Enforce 200 MB upload size limit in code
- [ ] Remove unused `python-magic` and `Pillow` deps (or start using them)
- [x] Add `LICENSE` file to the repository

Medium-term:
- [ ] HTTPS/TLS support documentation
- [ ] Structured logging
- [ ] Expand YARA rule library

Long-term (requires GPU / funding):
- [ ] Dynamic LLM sandbox analysis via Ollama (Llama-3 / Mistral)
- [ ] Fine-tuned prompt-injection detection model
- [ ] Advanced image forensics with Pillow

---

## Development

```bash
# Compile-check all source
python -m py_compile app.py pdf_sentinel/analyzer.py pdf_sentinel/crossref.py pdf_sentinel/plugins.py

# Run tests (when available)
pytest
```

### Adding YARA Rules

Append to `signatures.yara`:

```yara
rule MyRule {
    strings:
        $s = "pattern" nocase
    condition:
        any of them
}
```

---

## Contributing

1. Fork → branch → commit → PR.
2. Follow PEP 8; add tests for new features; update docs.

---

## Changelog

### 3.0 (2026-01-26)
Obfuscation detection, image forensics, citation spam, CrossRef DOI verification, plugin system, CPU optimization, Docker hardening, package restructure into `pdf_sentinel/`.

### 2.0 (2026-01-26)
PII detection (Presidio), structural risk analysis (pdfid), chunk-based semantic detection, non-root Docker, NFKC normalization.

### 1.0
Initial release — invisible text, YARA, semantic detection, Streamlit UI, Docker.

---

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

YARA · Sentence Transformers · Microsoft Presidio · CrossRef · qpdf · pdfid · Streamlit · spacy

---

**Version 3.0** · CPU-optimized · [Report issues](https://github.com/dblcpm/pdf-sentinel-sandbox/issues)
