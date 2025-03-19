#!/usr/bin/env bash
# exit on error
set -o errexit

# Update pip to latest version
python -m pip install --upgrade pip setuptools wheel

# Install dependencies in a specific order
pip install --no-cache-dir cryptography==41.0.7
pip install --no-cache-dir -r requirements.txt
