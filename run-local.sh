#!/usr/bin/env bash
# Loopback wrapper for the absorbed ARIA-X copy.
#
#   ./run-local.sh demo                 # offline, no key, deterministic
#   ./run-local.sh target               # start the bundled demo target on :8899
#   ./run-local.sh run --goal "..."     # live engagement, laptop config
#   ./run-local.sh doctor --llm         # full pre-flight
#
# Requires DEEPSEEK_API_KEY in the environment for anything that calls a model;
# the key is bridged to ARIA_X_API_KEY here and never written to disk.
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH=src
if [ -n "${DEEPSEEK_API_KEY:-}" ]; then export ARIA_X_API_KEY="$DEEPSEEK_API_KEY"; fi

case "${1:-}" in
  demo)   shift; exec python -m aria_x demo "$@" ;;
  target) shift; exec python examples/demo_target.py --port "${PORT:-8899}" --quiet "$@" ;;
  tools)  shift; exec python -m aria_x -c configs/laptop.toml tools "$@" ;;
  *)      exec python -m aria_x -c configs/laptop.toml "$@" ;;
esac
