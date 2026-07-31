#!/usr/bin/env bash
# fuzz.sh points ffuf at an already running main-httplinux server. Start it
# yourself first, in another terminal, so its log and any crash stay visible:
#
#	go run ./examples/http-linux -port 8080
#	./examples/http-linux/fuzz.sh                  # all cases
#	./examples/http-linux/fuzz.sh paths cookie     # named cases only
#	URL=http://localhost:9000 ./examples/http-linux/fuzz.sh
#
# Install ffuf with:  go install github.com/ffuf/ffuf/v2@latest
#
# Every case ends by reporting the server is still up: a case that "finds
# nothing" because the process died is the failure this is looking for.
set -u

URL="${URL:-http://localhost:8080}"
# Matched to the server's FixedNumGoroutines: in worker mode the router owns one
# exchange per goroutine and refuses a connection outright when none is free, so
# that count is what bounds concurrency. Going above it is correct backpressure,
# but it reaches ffuf as a connection error and hides the response a case was
# looking for. Raise it to exercise the drop path.
THREADS="${THREADS:-4}"

WORDDIR="$(mktemp -d)"
trap 'rm -rf "$WORDDIR"' EXIT

# ---------------------------------------------------------------------------
# Wordlists. Kept here rather than pulled from SecLists so a run is repeatable
# and every entry is aimed at the parser: percent escapes, separators the
# grammar gives meaning to, and lengths that cross the server's fixed buffers.
# ---------------------------------------------------------------------------
cat >"$WORDDIR/paths.txt" <<'EOF'
admin
login
search
health
echo
upload
users
files
users/alice
users/bob
users/carol
users/mallory
users/al%69ce
users/%zz
users/%2e%2e%2f
users/alice/extra
files/
files/readme.txt
files/logo.png
files/notes.md
files/a/b/c
files/%2e%2e/%2e%2e/etc/passwd
EOF

cat >"$WORDDIR/queries.txt" <<'EOF'
go
go+lang
go%20lang
%21%40%23
%zz
%
%2
a=b
a&b
a;b
""
EOF

cat >"$WORDDIR/passwords.txt" <<'EOF'
hunter2
password
admin
letmein
hunter2%00
hunter2+
hun%74er2
EOF

cat >"$WORDDIR/tokens.txt" <<'EOF'
s3cr3t-session-token
admin
""
"s3cr3t-session-token"
s3cr3t-session-token; debug
s3cr3t-session-token;debug
=====
;;;;;
EOF

cat >"$WORDDIR/headers.txt" <<'EOF'
plain
with spaces
%00%01%02
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF

cat >"$WORDDIR/names.txt" <<'EOF'
a.bin
report.pdf
../escape.txt
%2e%2e%2fescape.txt
EOF

# grow prints a line of n 'A's, for the cases that walk a value past a buffer.
grow() { printf 'A%.0s' $(seq "$1"); printf '\n'; }
{ for n in 8 64 512 1024 2048 4096 8192; do grow "$n"; done; } >"$WORDDIR/long.txt"

alive() {
	if curl -s -o /dev/null --max-time 5 "$URL/health"; then
		printf '  server alive\n\n'
	else
		printf '  *** SERVER DOWN after this case ***\n\n'
		exit 1
	fi
}

case_header() { printf '=== %s: %s\n' "$1" "$2"; }

# ---------------------------------------------------------------------------
# Cases. Each one drives a different part of the request through the parser.
# ---------------------------------------------------------------------------

# paths walks the mux: literal patterns, the "{id}" single-segment wildcard and
# the "{path...}" wildcard that swallows slashes. -mc all because a 404 from an
# unregistered path is a correct answer worth seeing next to the 200s.
fuzz_paths() {
	case_header paths "mux patterns, wildcards and percent escapes in the path"
	ffuf -u "$URL/FUZZ" -w "$WORDDIR/paths.txt" -t "$THREADS" -s -timeout 5 -mc all -fc 404
	alive
}

# recursion follows the "{path...}" wildcard down, which is the pattern a
# directory scanner exercises hardest.
fuzz_recursion() {
	case_header recursion "\"{path...}\" wildcard walked recursively"
	ffuf -u "$URL/files/FUZZ" -w "$WORDDIR/paths.txt" -t "$THREADS" -s -timeout 5 \
		-recursion -recursion-depth 2 -recursion-strategy greedy -mc all -fc 404
	alive
}

# longpath pushes the request-target past RequestHeaderBufferSize. The server
# should answer 431 or drop the connection, never serve a mangled path.
fuzz_longpath() {
	case_header longpath "request-target grown past the request header buffer"
	ffuf -u "$URL/FUZZ" -w "$WORDDIR/long.txt" -t 4 -s -timeout 5 -mc all
	alive
}

# query drives RequestQueryValue and the percent decoder, including escapes that
# do not decode, which must come back 400 and not half decoded.
fuzz_query() {
	case_header query "query string values, valid and malformed escapes"
	ffuf -u "$URL/search?q=FUZZ" -w "$WORDDIR/queries.txt" -t "$THREADS" -s -timeout 5 -mc all
	ffuf -u "$URL/search?q=go&limit=FUZZ" -w "$WORDDIR/queries.txt" -t "$THREADS" -s -timeout 5 -mc all
	case_header query "query value grown past the request header buffer"
	ffuf -u "$URL/search?q=FUZZ" -w "$WORDDIR/long.txt" -t 4 -s -timeout 5 -mc all
	alive
}

# form posts "application/x-www-form-urlencoded" bodies, the case the credential
# check answers 200 for and everything else 401.
fuzz_form() {
	case_header form "urlencoded body pairs; 200 is the credential that works"
	ffuf -u "$URL/login" -X POST -w "$WORDDIR/passwords.txt" \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		-d 'user=admin&pass=FUZZ' -t "$THREADS" -s -timeout 5 -mc all -fc 401
	case_header form "body grown past the form buffer, which may not grow"
	ffuf -u "$URL/login" -X POST -w "$WORDDIR/long.txt" \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		-d 'user=admin&pass=FUZZ' -t 4 -s -timeout 5 -mc all
	case_header form "pair count driven past the form's fixed pair table"
	ffuf -u "$URL/login?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=10&k=11&l=12&m=13&n=14&o=15&p=16&q=17" \
		-X POST -w "$WORDDIR/passwords.txt" \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		-d 'user=admin&pass=FUZZ' -t "$THREADS" -s -timeout 5 -mc all
	alive
}

# cookie drives the Cookie header parser: quoting, valueless attributes and the
# separators the grammar splits on.
fuzz_cookie() {
	case_header cookie "Cookie header values; 200 is the session that works"
	ffuf -u "$URL/admin" -w "$WORDDIR/tokens.txt" -b 'session=FUZZ' \
		-t "$THREADS" -s -timeout 5 -mc all -fc 403
	case_header cookie "cookie grown past the cookie buffer"
	ffuf -u "$URL/admin" -w "$WORDDIR/long.txt" -b 'session=FUZZ' -t 4 -s -timeout 5 -mc all
	alive
}

# headers fuzzes a header field value and the field count, /echo handing back
# the header block as the parser stored it.
fuzz_headers() {
	case_header headers "header field values echoed back through the parser"
	ffuf -u "$URL/echo" -w "$WORDDIR/headers.txt" -H 'X-Fuzz: FUZZ' \
		-t "$THREADS" -s -timeout 5 -mc all
	case_header headers "header value grown past the request header buffer"
	ffuf -u "$URL/echo" -w "$WORDDIR/long.txt" -H 'X-Fuzz: FUZZ' -t 4 -s -timeout 5 -mc all
	alive
}

# multipart fuzzes the part header block: the filename parameter picks whether a
# part is streamed to a sink or discarded.
fuzz_multipart() {
	case_header multipart "multipart part headers and filenames"
	ffuf -u "$URL/upload" -X POST -w "$WORDDIR/names.txt" \
		-H 'Content-Type: multipart/form-data; boundary=X' \
		-d $'--X\r\nContent-Disposition: form-data; name="f"; filename="FUZZ"\r\n\r\ndata\r\n--X--\r\n' \
		-t "$THREADS" -s -timeout 5 -mc all
	case_header multipart "part header grown past the multipart buffer, expect 413"
	ffuf -u "$URL/upload" -X POST -w "$WORDDIR/long.txt" \
		-H 'Content-Type: multipart/form-data; boundary=X' \
		-d $'--X\r\nContent-Disposition: form-data; name="f"; filename="FUZZ"\r\n\r\ndata\r\n--X--\r\n' \
		-t 4 -s -timeout 5 -mc all
	alive
}

# methods sends a method per registration and a few the server never names.
# "/echo" is registered without one, so any method reaches it; "/login" is
# POST only and everything else must 404 there.
fuzz_methods() {
	case_header methods "registered, unregistered and extension methods"
	printf 'GET\nPOST\nPUT\nDELETE\nPATCH\nHEAD\nOPTIONS\nTRACE\nPROPFIND\nBREW\n' >"$WORDDIR/methods.txt"
	ffuf -u "$URL/echo" -w "$WORDDIR/methods.txt" -X FUZZ -t "$THREADS" -s -timeout 5 -mc all
	ffuf -u "$URL/login" -w "$WORDDIR/methods.txt" -X FUZZ -t "$THREADS" -s -timeout 5 -mc all -fc 404
	alive
}

# clusterbomb crosses a path wordlist with a query wordlist, so the two parsers
# are driven by unrelated inputs in the same request.
fuzz_clusterbomb() {
	case_header clusterbomb "path and query fuzzed together, every combination"
	ffuf -u "$URL/PATH?q=QUERY" -mode clusterbomb \
		-w "$WORDDIR/paths.txt:PATH" -w "$WORDDIR/queries.txt:QUERY" \
		-t "$THREADS" -s -timeout 5 -mc all -fc 404
	alive
}

ALL=(paths recursion longpath query form cookie headers multipart methods clusterbomb)

main() {
	command -v ffuf >/dev/null || {
		echo "ffuf not found: go install github.com/ffuf/ffuf/v2@latest" >&2
		exit 1
	}
	curl -s -o /dev/null --max-time 5 "$URL/health" || {
		echo "no server at $URL: start it with 'go run ./examples/http-linux'" >&2
		exit 1
	}
	local cases=("$@")
	[ ${#cases[@]} -eq 0 ] && cases=("${ALL[@]}")
	for c in "${cases[@]}"; do
		"fuzz_$c" || { echo "unknown case: $c" >&2; exit 1; }
	done
	echo "all cases done, server still up"
}

main "$@"
