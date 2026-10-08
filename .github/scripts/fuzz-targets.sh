#!/usr/bin/env bash
# Prints the fuzz targets of the module as a JSON array of {dir, name}
# objects, for a workflow matrix. Fails if listing a package fails or if no
# target is found.
set -euo pipefail

dirs=$(go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.Dir}}{{end}}' ./...)
targets=$(mktemp)
trap 'rm -f "$targets"' EXIT
for dir in $dirs; do
	rel=.${dir#"$PWD"}
	names=$(go test -list '^Fuzz' "$rel")
	printf '%s\n' "$names" | jq -R --arg dir "$rel" 'select(test("^Fuzz[^[:space:]]+$")) | {dir: $dir, name: .}' >>"$targets"
done
jq -s -e 'length > 0' "$targets" >/dev/null
jq -sc . "$targets"
