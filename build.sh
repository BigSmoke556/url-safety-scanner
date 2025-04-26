#!/bin/bash

# Create output directory
mkdir -p dist

# Build for Linux
echo "🔨 Building for Linux..."
GOOS=linux GOARCH=amd64 go build -o dist/url-safety-scanner-linux ./cmd

# Build for Windows
echo "🔨 Building for Windows..."
GOOS=windows GOARCH=amd64 go build -o dist/url-safety-scanner-windows.exe ./cmd

# Build for MacOS
echo "🔨 Building for MacOS..."
GOOS=darwin GOARCH=amd64 go build -o dist/url-safety-scanner-macos ./cmd

echo "✅ Build complete! Binaries are in the 'dist/' folder."
