#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer tests for the xv6 code the fuzz targets run (built by build.sh
# with normal flags; this only RUNS them). xv6's own usertests need a RISC-V QEMU, so the oracle
# is the same upstream code linked natively:
#   fs_selftest    file-system syscalls (open/read/write/link/unlink/mkdir/chdir/pipe/fstat) on
#                  the mkfs image, the console device (line editing, read, write), exec of an ELF and patched images, asserting returned values and file contents
#   printk_selftest kernel printk output for each conversion
#   user_selftest  user printf output for each conversion, grep matches for ^ . * $ patterns
#   sh_test        the shell's exact stderr for a fixed script (parse, run, errors)
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"
BIN="$SRC/mayhem/bin"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

for b in fs_selftest printk_selftest user_selftest sh_test; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — run mayhem/build.sh" >&2; emit_ctrf xv6-selftest 0 1; exit 1; }
done

passed=0 failed=0
EXPECT_FS=35 EXPECT_PRINTK=8 EXPECT_USER=24   # number of checks each selftest makes

run_selftest() { # <expected count> <cmd...>
  local want="$1"; shift
  local out p f
  out="$("$@" 2>&1)"; echo "$out"
  p=$(grep -c '^PASS ' <<<"$out"); f=$(grep -c '^FAIL ' <<<"$out")
  passed=$((passed + p)); failed=$((failed + f))
  # A run that stops early (crash, or a no-op binary) reports fewer checks than it makes.
  if [ $((p + f)) -ne "$want" ]; then
    echo "FAIL $1: ran $((p + f)) checks, expected $want"; failed=$((failed + 1))
  fi
}
run_selftest "$EXPECT_FS" "$BIN/fs_selftest" "$SRC/README"
run_selftest "$EXPECT_PRINTK" "$BIN/printk_selftest"
run_selftest "$EXPECT_USER" "$BIN/user_selftest"

# The shell: prompts, exec failures, a subshell list, a syntax error, cd, redirection failure.
sh_got="$(printf 'echo hi\n(a;b)\na)\ncd /x\nx > z\n  \nfoo bar baz\n' | "$BIN/sh_test" 2>&1)"
sh_want="$(printf '$ exec echo failed\n$ exec a failed\nexec b failed\n$ leftovers: )\n\nsyntax\n$ cannot cd /x\n$ open z failed\n$ $ exec foo failed\n$ ')"
if [ "$sh_got" = "$sh_want" ]; then
  echo "PASS sh transcript"; passed=$((passed + 1))
else
  echo "FAIL sh transcript"; diff <(echo "$sh_want") <(echo "$sh_got"); failed=$((failed + 1))
fi

emit_ctrf xv6-selftest "$passed" "$failed"
