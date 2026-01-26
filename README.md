# PDF Sentinel 🔍

Python-based PDF scanner for prompt injection checks suitable for journal editors

## Overview

PDF Sentinel is a forensic PDF analysis tool designed to detect:
- **Invisible Text**: Hidden text using white-on-white or invisible rendering modes
- **Suspicious Keywords**: YARA-based detection of prompt injection patterns
- **Semantic Injection**: ML-powered detection using sentence embeddings
- **Hidden Commands**: JavaScript, launch actions, and other malicious PDF features

## Features

- 🔍 **Invisible Text Detection**: Detects text rendered invisible through color manipulation or rendering modes
- 🎯 **YARA Integration**: Comprehensive keyword-based pattern matching
- 🧠 **Semantic Analysis**: Uses `all-MiniLM-L6-v2` embeddings for deep content analysis
- 🛡️ **Risk Scoring**: Automated risk assessment with actionable recommendations
- 🔒 **Secure Processing**: Proper tempfile handling and cleanup
- 🐳 **Dockerized**: Easy deployment with all dependencies bundled

## Tech Stack

- **Python 3.11**
- **Streamlit** - Web UI framework
- **YARA** - Pattern matching engine
- **Sentence Transformers** - Semantic embedding model
- **qpdf** - PDF manipulation tool
- **Docker** - Containerization

## Installation

### Using Docker (Recommended)

```bash
# Build and run with docker-compose
docker-compose up --build

# Or build manually
docker build -t pdf-sentinel .
docker run -p 8501:8501 pdf-sentinel
```

Access the application at: http://localhost:8501

### Local Installation

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get install qpdf libimage-exiftool-perl libyara-dev gcc g++

# Install Python dependencies
pip install -r requirements.in

# Run the application
streamlit run app.py
```

## Usage

1. **Upload PDF**: Click "Choose a PDF file to analyze" and upload your PDF
2. **Configure Settings**: Adjust semantic detection threshold in the sidebar
3. **Analyze**: Click "🔍 Analyze PDF" button
4. **Review Results**: Check the risk assessment and detailed findings in each tab

## Architecture

### Components

- **app.py**: Streamlit web interface
- **analyzer.py**: Core PDF analysis logic
- **signatures.yara**: YARA rules for keyword detection
- **Dockerfile**: Container configuration
- **requirements.in**: Python dependencies

### Analysis Pipeline

1. **PDF Uncompression**: Uses `qpdf --qdf --object-streams=disable` to uncompress PDF for analysis
2. **Invisible Text Detection**: Regex-based detection of:
   - `1 1 1 rg` (white RGB color)
   - `1 g` (white grayscale)
   - `3 Tr` (invisible rendering mode)
3. **YARA Scanning**: Matches against predefined rules for suspicious keywords
4. **Semantic Analysis**: Compares text embeddings against known injection patterns
5. **Risk Scoring**: Aggregates findings into a comprehensive risk score

## YARA Rules

The tool includes three main YARA rule categories:

- **SuspiciousKeywords**: Detects prompt injection attempts
- **HiddenCommands**: Identifies JavaScript and action commands
- **EncodedContent**: Flags excessive encoding/obfuscation

## Security Considerations

- All PDF processing happens in isolated temporary directories
- Temporary files are securely cleaned up after analysis
- No external network calls during analysis
- File uploads are validated and sandboxed
- **PyTorch Version**: Uses PyTorch ≥2.6.0 to address CVE vulnerabilities in earlier versions
- The application does not use `torch.load()` directly, avoiding deserialization risks

## Development

### Running Tests

```bash
# Install development dependencies
pip install -r requirements.in

# Run tests (if available)
pytest
```

### Customizing YARA Rules

Edit `signatures.yara` to add custom detection patterns:

```yara
rule CustomRule {
    meta:
        description = "Your description"
    strings:
        $pattern1 = "suspicious text" nocase
    condition:
        any of them
}
```

## License

MIT

## Contributing

Contributions welcome! Please submit pull requests or open issues for bugs and feature requests.

## Acknowledgments

- YARA project for pattern matching
- Sentence Transformers for embedding models
- qpdf for PDF manipulation
