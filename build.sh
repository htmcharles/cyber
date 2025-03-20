#!/usr/bin/env bash
# exit on error
set -o errexit

# Force upgrade pip first
pip install --upgrade pip

# Install build dependencies
pip install -r requirements.txt

# Set environment variables to avoid Rust compilation
export CRYPTOGRAPHY_DONT_BUILD_RUST=1
export BCRYPT_DONT_BUILD_RUST=1

# Install dependencies with specific options
pip install --no-cache-dir --only-binary :all: cryptography==41.0.7
pip install --no-cache-dir --only-binary :all: bcrypt==4.0.1
