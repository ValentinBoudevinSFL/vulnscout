#!/bin/bash
set -euo pipefail

ROOT_DIR=$(readlink -f "$(dirname "$0")/../..")
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "$TEST_DIR/bin"
cat > "$TEST_DIR/bin/podman" <<'EOF'
#!/bin/bash
set -euo pipefail

case "$1" in
    ps)
        echo "vulnscout"
        ;;
    cp)
        ;;
    exec)
        printf '%q ' "$@" >> "$VULNSCOUT_TEST_LOG"
        printf '\n' >> "$VULNSCOUT_TEST_LOG"
        exit "${VULNSCOUT_TEST_EXEC_EXIT:-0}"
        ;;
    *)
        echo "Unexpected podman command: $*" >&2
        exit 99
        ;;
esac
EOF
chmod +x "$TEST_DIR/bin/podman"

SBOM="$TEST_DIR/input.spdx.json"
printf '{}\n' > "$SBOM"
export PATH="$TEST_DIR/bin:/usr/bin:/bin"
export VULNSCOUT_BUILD_DIR="$TEST_DIR/build"
export VULNSCOUT_TEST_LOG="$TEST_DIR/container.log"

"$ROOT_DIR/vulnscout" help > "$TEST_DIR/help.txt"
grep -q -- '--refresh-vulnerability-data' "$TEST_DIR/help.txt"
awk '
    /^ +(--|start\||stop\||restart\|)/ {
        if ($0 !~ /^    [^ ]/) {
            print "Misaligned help command: " $0 > "/dev/stderr"
            failed = 1
        }
        text = substr($0, 5)
        if (match(text, /  +[^ ]/) && RSTART + RLENGTH + 3 != 37) {
            print "Misaligned help description: " $0 > "/dev/stderr"
            failed = 1
        }
    }
    /^ +[^ ]/ {
        column = match($0, /[^ ]/)
        if (column > 9 && column != 37) {
            print "Misaligned help continuation: " $0 > "/dev/stderr"
            failed = 1
        }
    }
    /^ +vulnscout / && $0 !~ /^  vulnscout / {
        print "Misaligned help example: " $0 > "/dev/stderr"
        failed = 1
    }
    END { exit failed }
' "$TEST_DIR/help.txt"
"$ROOT_DIR/vulnscout" --help > "$TEST_DIR/help-flag.txt"
cmp "$TEST_DIR/help.txt" "$TEST_DIR/help-flag.txt"
"$ROOT_DIR/vulnscout" -h > "$TEST_DIR/help-short.txt"
cmp "$TEST_DIR/help.txt" "$TEST_DIR/help-short.txt"
"$ROOT_DIR/vulnscout" > "$TEST_DIR/help-default.txt"
cmp "$TEST_DIR/help.txt" "$TEST_DIR/help-default.txt"

"$ROOT_DIR/vulnscout" --refresh-vulnerability-data
grep -q -- '/scan/src/entrypoint.sh --refresh-vulnerability-data' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --refresh-vulnerability-data
grep -q -- '/scan/src/entrypoint.sh --project cli --refresh-vulnerability-data' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --variant default --refresh-vulnerability-data
grep -q -- '/scan/src/entrypoint.sh --variant default --project cli --refresh-vulnerability-data' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --match-condition affected
grep -q -- '/scan/src/entrypoint.sh --match-condition affected' "$VULNSCOUT_TEST_LOG"
if grep -q -- '--project\|--variant' "$VULNSCOUT_TEST_LOG"; then
    echo "Default scope was forwarded as explicit scope." >&2
    exit 1
fi

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --match-condition affected
grep -q -- '/scan/src/entrypoint.sh --project cli --match-condition affected' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --variant release --match-condition affected
grep -q -- '/scan/src/entrypoint.sh --project cli --variant release --match-condition affected' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --report summary.adoc
grep -q -- '/scan/src/entrypoint.sh --project default --report summary.adoc' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --report summary.adoc
grep -q -- '/scan/src/entrypoint.sh --project cli --report summary.adoc' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --variant release --report summary.adoc
grep -q -- '/scan/src/entrypoint.sh --project cli --variant release --report summary.adoc' "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --add-spdx "$SBOM" --match-condition affected
grep -q -- '--project cli --add-spdx /tmp/vulnscout_stage_input.spdx.json --match-condition affected' \
    "$VULNSCOUT_TEST_LOG"
if grep -q -- '--variant' "$VULNSCOUT_TEST_LOG"; then
    echo "Default variant was forwarded as an explicit variant." >&2
    exit 1
fi

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --project cli --variant default \
    --add-spdx "$SBOM" --refresh-vulnerability-data
grep -q -- \
    '--project cli --variant default --add-spdx /tmp/vulnscout_stage_input.spdx.json --refresh-vulnerability-data' \
    "$VULNSCOUT_TEST_LOG"

: > "$VULNSCOUT_TEST_LOG"
"$ROOT_DIR/vulnscout" --add-spdx "$SBOM"
if grep -q -- '--refresh-vulnerability-data' "$VULNSCOUT_TEST_LOG"; then
    echo "Refresh flag was propagated when absent." >&2
    exit 1
fi

export VULNSCOUT_TEST_EXEC_EXIT=7
if "$ROOT_DIR/vulnscout" --add-spdx "$SBOM" --refresh-vulnerability-data; then
    echo "Container execution failure was not propagated." >&2
    exit 1
else
    status=$?
fi
if [[ "$status" -ne 7 ]]; then
    echo "Expected exit 7, got $status." >&2
    exit 1
fi

echo "Host wrapper scope tests passed."
