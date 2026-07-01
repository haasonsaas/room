#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ROOM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "$ROOT/.codex" "$ROOT/.claude"
cp "$ROOM_ROOT/hooks/codex/hooks.json" "$ROOT/.codex/hooks.json"
cp "$ROOM_ROOT/hooks/claude/settings.json" "$ROOT/.claude/settings.json"

echo "Installed Room hook templates into:"
echo "  $ROOT/.codex/hooks.json"
echo "  $ROOT/.claude/settings.json"
echo
echo "Install roomctl if needed:"
echo "  go install github.com/haasonsaas/room/cmd/roomctl@latest"

