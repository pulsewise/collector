#!/bin/bash
set -e

VERSION="${VERSION:-0.1.0}"

go build -ldflags "-X main.version=${VERSION}" -o pulsewise-collector .
echo "Built: pulsewise-collector (v${VERSION})"
