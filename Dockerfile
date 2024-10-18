# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies
RUN pip install --upgrade pip && \
    pip install pycryptodome loguru

# Create app directory
WORKDIR /app

# Copy scripts and necessary files
COPY envcrypt.py /app/envcrypt.py
COPY keymanager.py /app/keymanager.py

# Make the scripts executable
RUN chmod +x /app/envcrypt.py /app/keymanager.py

# Set the entrypoint to execute EnvCryptor
ENTRYPOINT ["python", "/app/envcrypt.py"]
