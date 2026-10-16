# Use official minimal Rust base image (Debian Bookworm)
# Platform target is passed dynamically via Makefile (docker build --platform)
FROM rust:1.98.1-slim-bookworm

# Install required system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    musl-tools \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set application working directory
WORKDIR /app

# Configure cargo registry caching via environment variables
ENV CARGO_HOME=/usr/local/cargo

# Source code is mounted via volume in local development;
# for self-contained CI builds, copy source files:
# COPY . .
