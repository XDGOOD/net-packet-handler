#!/usr/bin/env bash
# ==============================================================================
# 🛡️ AEGS v6 Titan Protocol - Root CLI Wrapper
# Forwards execution to scripts/manage.sh
# ==============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/scripts/manage.sh" "$@"
