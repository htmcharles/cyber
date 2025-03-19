#!/usr/bin/env bash
# exit on error
set -o errexit

# Update pip and install build dependencies first
python -m pip install --upgrade pip
python -m pip install --upgrade setuptools wheel

# Install dependencies with specific options for cryptography
export CRYPTOGRAPHY_DONT_BUILD_RUST=1
pip install --no-cache-dir -r requirements.txt
