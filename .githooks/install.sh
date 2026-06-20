#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "${repo_root}"

git config core.hooksPath .githooks
chmod +x .githooks/commit-msg

echo "Installed git hooks from .githooks (core.hooksPath=.githooks)"