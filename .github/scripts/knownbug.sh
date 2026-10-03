#!/usr/bin/env bash
# Runs tagged-only TestKnownBug_* tests and requires ordinary test failures.
# Passing tests must become untagged regression tests. See docs/TESTING.md.
set -uo pipefail

summary=${GITHUB_STEP_SUMMARY:-/dev/null}
echo "| Package | Known bug | Status |" >>"$summary"
echo "|---|---|---|" >>"$summary"
status=0
if ! packages=$(go list -tags=knownbug ./... 2>&1); then
	echo "::error::knownbug package discovery failed"
	echo "$packages"
	exit 1
fi
files=$(grep -rlx --include='*_test.go' '//go:build knownbug' . 2>&1)
rc=$?
if (( rc == 1 )); then
	echo "No knownbug tests registered."
	exit 0
elif (( rc != 0 )); then
	echo "::error::knownbug file discovery failed"
	echo "$files"
	exit 1
fi
if ! dirs=$(printf '%s\n' "$files" | xargs -d '\n' -n1 dirname | sort -u); then
	echo "::error::knownbug directory discovery failed"
	exit 1
fi
IFS=$'\n'
for dir in $dirs; do
	if ! tagged=$(go test -tags=knownbug -timeout=1m -list '^TestKnownBug_' "$dir" 2>&1); then
		echo "::error::$dir: tagged test discovery failed"
		echo "$tagged"
		status=1
		continue
	fi
	if ! untagged=$(go test -timeout=1m -list '^TestKnownBug_' "$dir" 2>&1); then
		echo "::error::$dir: untagged test discovery failed"
		echo "$untagged"
		status=1
		continue
	fi
	if ! names=$(jq -nr --arg tagged "$tagged" --arg untagged "$untagged" '
		($tagged | split("\n") | map(select(test("^TestKnownBug_[^[:space:]]+$")))) -
		($untagged | split("\n")) | .[]'); then
		echo "::error::$dir: knownbug test discovery failed"
		status=1
		continue
	fi
	if [[ -z $names ]]; then
		echo "::error::$dir: knownbug files register no tagged-only TestKnownBug_* tests"
		status=1
		continue
	fi
	for name in $names; do
		output=$(go test -json -tags=knownbug -count=1 -timeout=1m -run "^${name}\$" "$dir" 2>&1)
		rc=$?
		if (( rc == 1 )) && jq -e -s --arg name "$name" '
			any(.[]; .Test == $name and .Action == "run") and
			any(.[]; .Test == $name and .Action == "fail") and
			all(.[]; .Test != $name or (.Action != "skip" and .Action != "pass")) and
			all(.[]; (.Output // "" | test("panic:|fatal error:|WARNING: DATA RACE|race detected during execution of test|test timed out|signal:|SIG(SEGV|BUS|ABRT|QUIT|ILL|FPE)"; "i")) | not)
		' <<<"$output" >/dev/null; then
			echo "known bug: $dir $name"
			echo "| $dir | $name | fails |" >>"$summary"
		else
			echo "::error::$dir $name: expected an ordinary named test failure, got exit $rc; promote passing tests by dropping their knownbug build tag"
			echo "$output"
			echo "| $dir | $name | unexpected result |" >>"$summary"
			status=1
		fi
	done
done
exit $status
