#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

python3 -m compileall -q contracts tests
python3 -m unittest discover -s tests -v

if command -v genvm-lint >/dev/null 2>&1; then
  lint_cmd="genvm-lint"
elif [[ -x .venv/bin/genvm-lint ]]; then
  lint_cmd=".venv/bin/genvm-lint"
else
  echo "genvm-lint is required; install requirements-dev.txt" >&2
  exit 1
fi

"$lint_cmd" check contracts/invariant_lens.py

schema_tmp="$(mktemp)"
trap 'rm -f "$schema_tmp"' EXIT
"$lint_cmd" schema contracts/invariant_lens.py --output "$schema_tmp" >/dev/null
diff -u contracts/contract-metadata/invariant_lens.schema.json "$schema_tmp"
