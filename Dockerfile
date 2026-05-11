FROM python:3.11-slim

# Install system dependencies including tshark
RUN apt-get update && apt-get install -y \
    tshark \
    wireshark-common \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY knowledge.db . 2>/dev/null || echo "No knowledge.db found, will create on first run"

# Create directory for temporary files
RUN mkdir -p /tmp/pcap_uploads

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Run Streamlit
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
