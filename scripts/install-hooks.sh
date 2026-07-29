#!/usr/bin/env bash
set -euo pipefail
HOOK_PATH="$(git rev-parse --git-dir)/hooks/pre-push"
cat > "$HOOK_PATH" <<'HOOK'
#!/usr/bin/env bash
exec ./scripts/ci-local.sh
HOOK
chmod +x "$HOOK_PATH"
echo "pre-push hook installed — ci-local.sh will now run before every push."
