#!/usr/bin/env bash
# Auth-lane wrapper for the absorbed ARIA-X copy.
#
#   ./run-auth.sh lab                     # start the vulnerable lab on :8899
#   ./run-auth.sh verify                  # score the auth capability, no model, no key
#   ./run-auth.sh goals                   # list goal templates
#   ./run-auth.sh goal auth-presence      # one bounded auth run against the lab
#   ./run-auth.sh suite                   # verify, then every goal, then summarise
#
# Needs DEEPSEEK_API_KEY only for the goal/suite runs; verify is offline.
# The key is bridged to ARIA_X_API_KEY here and never written to disk.
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH=src
if [ -n "${DEEPSEEK_API_KEY:-}" ]; then export ARIA_X_API_KEY="$DEEPSEEK_API_KEY"; fi
# The lab ships a local solver stand-in; point the token lane at it unless a real
# solver URL (ARIAX_SOLVER_URL) or a keyed service (ARIAX_CAPTCHA_KEY) is supplied.
if [ -z "${ARIAX_SOLVER_URL:-}" ] && [ -z "${ARIAX_CAPTCHA_KEY:-}" ]; then
  export ARIAX_SOLVER_URL="http://127.0.0.1:${PORT:-8899}/solver"
fi

# Chrome instances we launched are killed by profile path, never the operator's own.
close_browsers() {
  [ "${ARIAX_KEEP_BROWSER:-0}" = "1" ] && return 0
  powershell -NoProfile -Command     "Get-CimInstance Win32_Process -Filter \"Name='chrome.exe'\" | Where-Object { \$_.CommandLine -like '*aria-x*profile_*' } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }"     >/dev/null 2>&1 || true
}

case "${1:-}" in
  lab)
    shift; exec python lab/lab_app.py --port "${PORT:-8899}" "$@" ;;
  verify)
    shift; exec python lab/verify_auth_capability.py "$@" ;;
  goals)
    shift
    printf '%-22s %s\n' NAME FIRST-LINE
    for f in goals/*.md; do
      [ "$(basename "$f")" = "README.md" ] && continue
      printf '%-22s %s\n' "$(basename "$f" .md)" "$(head -1 "$f")"
    done ;;
  goal)
    shift
    name="${1:?goal name required (see ./run-auth.sh goals)}"; shift
    file="goals/${name}.md"
    [ -f "$file" ] || { echo "no such goal: $name" >&2; exit 2; }
    goal="$(sed '/^$/d' "$file")"
    python -m aria_x -c configs/auth-lane.toml run --name "auth:$name" --goal "$goal" "$@"
    close_browsers ;;

  suite)
    shift
    python lab/verify_auth_capability.py
    for f in goals/*.md; do
      [ "$(basename "$f")" = "README.md" ] && continue
      name="$(basename "$f" .md)"
      echo "=== $name"
      python -m aria_x -c configs/auth-lane.toml run --name "auth:$name" \
        --goal "$(sed '/^$/d' "$f")" --quiet "$@" || echo "  (run failed)"
    done ;;
  *)
    exec python -m aria_x -c configs/auth-lane.toml "$@" ;;
esac
