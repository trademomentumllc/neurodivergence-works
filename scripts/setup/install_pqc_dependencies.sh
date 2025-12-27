#!/bin/bash
# Install PQC dependencies for all languages

echo "🔐 Installing Post-Quantum Cryptography Dependencies"

# Python
echo "📦 Installing Python PQC libraries..."
pip install pqcrypto liboqs-python cryptography

# Rust
echo "🦀 Installing Rust PQC libraries..."
cd ../../code/rust && cargo build --release
cd ../../scripts/setup

# Go (using circl)
echo "🐹 Installing Go PQC libraries..."
cd ../../code/go && go mod download
cd ../../scripts/setup

echo "✅ PQC dependencies installed successfully"
