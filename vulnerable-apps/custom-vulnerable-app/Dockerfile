# Dockerfile for Custom Vulnerable Application
FROM python:3.11-slim

LABEL description="Intentionally vulnerable Flask application for security testing"
LABEL purpose="CPG-based analysis testing and validation"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application files
COPY requirements.txt .
COPY app.py .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create directory for database
RUN mkdir -p /tmp && chmod 777 /tmp

# Expose port
EXPOSE 8888

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8888/health || exit 1

# Run application
CMD ["python", "app.py"]
