#!/usr/bin/env bash
# Runs each TestKnownBug_* test of the files built with -tags=knownbug and
# fails if one of them passes, since its bug is then fixed and the test must
# become a regression test by dropping the build tag. See docs/TESTING.md.
set -uo pipefail

summary=${GITHUB_STEP_SUMMARY:-/dev/null}
echo "| Package | Known bug | Status |" >>"$summary"
echo "|---|---|---|" >>"$summary"
status=0
dirs=$(grep -rlx --include='*_test.go' '//go:build knownbug' . | xargs -r -n1 dirname | sort -u)
for dir in $dirs; do
	if ! names=$(go test -tags=knownbug -list '^TestKnownBug_' "$dir"); then
		echo "::error::$dir: knownbug tests do not build"
		echo "$names"
		status=1
		continue
	fi
	for name in $(echo "$names" | grep '^TestKnownBug_'); do
		if go test -tags=knownbug -count=1 -run "^${name}\$" "$dir" >/dev/null 2>&1; then
			echo "::error::$dir $name passes: drop its knownbug build tag"
			echo "| $dir | $name | passes, promote it |" >>"$summary"
			status=1
		else
			echo "known bug: $dir $name"
			echo "| $dir | $name | fails |" >>"$summary"
		fi
	done
done
exit $status
