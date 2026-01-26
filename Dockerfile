# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    qpdf \
    libimage-exiftool-perl \
    libyara-dev \
    gcc \
    g++ \
    poppler-utils \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.in requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download models to bake them into the image
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')" && \
    python -m spacy download en_core_web_sm

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

# Copy application files
COPY --chown=appuser:appuser app.py .
COPY --chown=appuser:appuser analyzer.py .
COPY --chown=appuser:appuser signatures.yara .

# Switch to non-root user
USER appuser

# Expose Streamlit default port
EXPOSE 8501

# Run the application
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
