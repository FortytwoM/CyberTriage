#!/usr/bin/env sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python_bin=${PYTHON:-}
if [ -z "$python_bin" ]; then
  if command -v python3 >/dev/null 2>&1; then
    python_bin=python3
  else
    python_bin=python
  fi
fi
exec "$python_bin" "$root/tools/cybertriage-license/issue.py" \
  --input-dir "$root/input" \
  --output-dir "$root/output" \
  --licenses-dir "$root/licenses" \
  "$@"
