#!/bin/bash
set -e

VERSION="${VERSION:-$(cat VERSION)}"

go build -ldflags "-X main.version=${VERSION}" -o pulsewise-collector .
echo "Built: pulsewise-collector (v${VERSION})"
