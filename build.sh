#!/usr/bin/env bash
# exit on error
set -o errexit

# Update pip and install build dependencies
python -m pip install --upgrade pip setuptools wheel

# Set environment variables to avoid Rust compilation
export CRYPTOGRAPHY_DONT_BUILD_RUST=1
export BCRYPT_DONT_BUILD_RUST=1

# Install dependencies with specific options
pip install --no-cache-dir --only-binary :all: cryptography==41.0.7
pip install --no-cache-dir --only-binary :all: bcrypt==4.0.1
pip install --no-cache-dir -r requirements.txt
