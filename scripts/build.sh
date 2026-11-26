#!/usr/bin/env bash
# Compile every non-correlation Sigma rule in rules/sigma/ to an Elastic
# Lucene/KQL query in rules/elastic/.
#
#   scripts/build.sh          write the compiled .kql files
#   scripts/build.sh --check  fail if any committed .kql differs from a fresh build
#
# Correlation rules (password spraying, account lockout burst) can't be
# compiled to a query string. Their Kibana rule configs in rules/elastic/
# are maintained by hand.
set -euo pipefail

cd "$(dirname "$0")/.."
mode="${1:-write}"
status=0

for rule in rules/sigma/*.yml; do
  name="$(basename "$rule" .yml)"
  if grep -q '^correlation:' "$rule"; then
    echo "skip   $name (correlation rule)"
    continue
  fi

  compiled="$(sigma convert -t lucene \
    -p pipelines/lab_winlogbeat.yml -p ecs_windows \
    "$rule" 2>/dev/null | grep -v '^Parsing Sigma rules')"
  out="rules/elastic/$name.kql"

  if [[ "$mode" == "--check" ]]; then
    if [[ ! -f "$out" ]] || [[ "$compiled" != "$(cat "$out")" ]]; then
      echo "DRIFT  $name: $out does not match the compiled Sigma rule"
      echo "       expected: $compiled"
      status=1
    else
      echo "ok     $name"
    fi
  else
    printf '%s\n' "$compiled" > "$out"
    echo "wrote  $out"
  fi
done

if [[ "$status" -ne 0 ]]; then
  echo
  echo "Run scripts/build.sh and commit the result."
fi
exit "$status"
