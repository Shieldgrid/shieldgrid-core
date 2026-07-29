#!/usr/bin/env bash
set -euo pipefail

echo "==> cargo fmt --check"
cargo fmt --all -- --check

echo "==> cargo build"
cargo build --locked

echo "==> cargo clippy"
cargo clippy --locked --all-targets -- -D warnings

echo "==> cargo test"
cargo test --locked

echo "✅ All checks passed locally — safe to push."
