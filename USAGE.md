# PDF Sentinel - Usage Examples

## Quick Start

### Using Docker (Recommended)

```bash
# Build and run
docker-compose up --build

# Access at http://localhost:8501
```

### Local Installation

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get install qpdf libimage-exiftool-perl libyara-dev gcc g++

# Install Python dependencies
pip install -r requirements.in

# Run the application
streamlit run app.py
```

## Using the Web Interface

1. **Upload PDF**: Click "Browse files" or drag and drop a PDF file
2. **Configure Settings**: Adjust the semantic detection threshold if needed
3. **Analyze**: Click the "🔍 Analyze PDF" button
4. **Review Results**: Check each tab for different types of detections

## Command Line Usage

You can also use the analyzer programmatically:

```python
from analyzer import PDFAnalyzer

# Initialize analyzer
analyzer = PDFAnalyzer('signatures.yara', enable_semantic=True)

# Analyze a PDF file
results = analyzer.analyze_pdf('/path/to/file.pdf')

# Get risk assessment
risk_level, risk_score = analyzer.get_risk_score(results)

print(f"Risk Level: {risk_level}")
print(f"Risk Score: {risk_score}/100")
print(f"Invisible Text Detections: {len(results['invisible_text'])}")
print(f"YARA Matches: {len(results['yara_matches'])}")
print(f"Semantic Detections: {len(results['semantic_detections'])}")
```

## Environment Variables

- `ENABLE_SEMANTIC_DETECTION`: Set to `true` to enable semantic analysis (requires downloading ML model)
  ```bash
  export ENABLE_SEMANTIC_DETECTION=true
  streamlit run app.py
  ```

## Docker Deployment

### Build Custom Image

```bash
docker build -t pdf-sentinel:latest .
```

### Run Container

```bash
docker run -p 8501:8501 \
  -e ENABLE_SEMANTIC_DETECTION=true \
  pdf-sentinel:latest
```

### Using Docker Compose

```bash
# Start in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Analysis Results Interpretation

### Risk Levels

- **CLEAN** (0 points): No threats detected
- **LOW** (1-24 points): Minor concerns, likely safe
- **MEDIUM** (25-49 points): Several suspicious patterns found
- **HIGH** (50-79 points): Significant threats detected
- **CRITICAL** (80-100 points): Multiple severe threats

### Detection Types

1. **Invisible Text**: Text rendered invisible through:
   - White RGB color (1 1 1 rg)
   - White grayscale (1 g)
   - Invisible rendering mode (3 Tr)

2. **YARA Matches**: Pattern-based detection of:
   - Prompt injection keywords
   - Hidden JavaScript/commands
   - Excessive encoding

3. **Semantic Detection**: ML-based similarity analysis for:
   - Instruction override attempts
   - Data exfiltration patterns
   - Role manipulation

## Custom YARA Rules

Edit `signatures.yara` to add your own detection patterns:

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

## Troubleshooting

### Model Download Issues

If semantic detection fails to load:
- Check internet connectivity
- Ensure HuggingFace is accessible
- Or disable semantic detection: `ENABLE_SEMANTIC_DETECTION=false`

### qpdf Not Found

Install qpdf:
```bash
# Ubuntu/Debian
sudo apt-get install qpdf

# macOS
brew install qpdf

# CentOS/RHEL
sudo yum install qpdf
```

### YARA Errors

Ensure libyara-dev is installed:
```bash
sudo apt-get install libyara-dev
pip install --upgrade yara-python
```

## API Reference

### PDFAnalyzer Class

```python
class PDFAnalyzer:
    def __init__(self, yara_rules_path: str = "signatures.yara", 
                 enable_semantic: bool = True)
    
    def analyze_pdf(self, pdf_path: str) -> Dict[str, any]
    
    def get_risk_score(self, results: Dict[str, any]) -> Tuple[str, int]
    
    def detect_invisible_text(self, pdf_content: str) -> List[Dict[str, any]]
    
    def scan_with_yara(self, content: str) -> List[Dict[str, any]]
    
    def detect_semantic_injection(self, text: str, threshold: float = 0.7) 
        -> List[Dict[str, any]]
```

## Performance Considerations

- **Small PDFs** (<1MB): Analysis typically takes 1-3 seconds
- **Medium PDFs** (1-10MB): Analysis may take 5-15 seconds
- **Large PDFs** (>10MB): May take 30+ seconds
- **Semantic Detection**: Adds 5-10 seconds for model loading (first run only)

## Security Notes

- All PDF processing happens in isolated temporary directories
- Temporary files are automatically cleaned up after analysis
- No external network calls during analysis (except model download)
- File uploads are validated and sandboxed
