#!/usr/bin/env bash
# exit on error
set -o errexit

# Update pip and install build dependencies first
python -m pip install --upgrade pip
python -m pip install --upgrade setuptools wheel

# Install cryptography separately with pre-built wheels
pip install --no-cache-dir cryptography==41.0.7 --no-binary cryptography

# Install remaining dependencies
pip install --no-cache-dir -r requirements.txt
