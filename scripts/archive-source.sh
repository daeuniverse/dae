#!/usr/bin/env bash
# Run after initializing submodules and creating bundled/, before building.
set -euo pipefail

# The shared runner cache is outside the source archive.
GOMODCACHE="$PWD/go-mod" go mod download -modcacherw

zip -9qr bundled/dae-full-src.zip . \
  -x '.git' '.git/*' '*/.git' '*/.git/*' 'bundled/*'
tar -I 'xz -9' -cf bundled/dae-full-src.tar.xz --exclude=.git --exclude=bundled .
