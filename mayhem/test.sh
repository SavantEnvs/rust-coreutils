#!/usr/bin/env bash
#
# rust-coreutils/mayhem/test.sh — RUN uutils/coreutils' own test suites for the integrated utils
# and emit a CTRF summary. exit 0 iff no test failed.
#
# PATCH-grade oracle: the uu_split crate ships unit tests, and the workspace
# `tests/by-util/test_split.rs` integration tests exercise the real CLI against GNU-compatible expected
# output. These assert concrete behavior, so a no-op / "exit(0)" / output-altering patch CANNOT pass.
# This script only RUNS the suite via `cargo test`; it never builds fuzz targets.
#
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SRC:=/mayhem}"
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not available — cannot run the test suite" >&2
  emit_ctrf "cargo-test" 0 1 0; exit 2
fi

# The integrated fuzz subset → the util crates whose tests we run. The workspace exposes per-util
# unit tests via `-p uu_<util>`, and CLI integration tests as features on the top-level `coreutils`
# crate (tests/by-util/test_<util>.rs, gated behind feature `test_<util>` / the util feature).
# Mining branch: only split is fuzzed, so only split is tested (keeps the image layer small).
UTILS=(split)
PKG_ARGS=()
for u in "${UTILS[@]}"; do PKG_ARGS+=( -p "uu_$u" ); done

echo "=== running cargo test for integrated utils: ${UTILS[*]} ==="
# Use the image's DEFAULT toolchain (the Dockerfile pins it to the same nightly the fuzz build
# uses), so no `+toolchain` override. --no-fail-fast so we count every test; RUSTFLAGS cleared so
# it inherits nothing from the sanitizer build.
# Build into a scratch dir removed afterwards: the workspace target dir would add GBs to the image.
CARGO_TARGET_DIR="$(mktemp -d)"; export CARGO_TARGET_DIR
trap 'rm -rf "$CARGO_TARGET_DIR"' EXIT
out="$(RUSTFLAGS="" cargo test "${PKG_ARGS[@]}" --no-fail-fast --jobs "$MAYHEM_JOBS" 2>&1)"; rc=$?
echo "$out"
# CLI known-answer tests (tests/by-util/test_split.rs): assert split's real output, built for split only.
out2="$(RUSTFLAGS="" cargo test --no-default-features --features split --test tests --no-fail-fast --jobs "$MAYHEM_JOBS" -- test_split 2>&1)"; rc2=$?
echo "$out2"
out="$out"$'\n'"$out2"
[ "$rc" -eq 0 ] && rc=$rc2

# libtest prints one line per test binary:
#   test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; ...
# Sum across all binaries.
PASSED=0; FAILED=0; IGNORED=0
while read -r p f i; do
  PASSED=$(( PASSED + p )); FAILED=$(( FAILED + f )); IGNORED=$(( IGNORED + i ))
done < <(printf '%s\n' "$out" \
  | sed -n 's/^test result:.* \([0-9][0-9]*\) passed; \([0-9][0-9]*\) failed; \([0-9][0-9]*\) ignored.*/\1 \2 \3/p')

# If we parsed no result lines, fall back to the cargo exit code (e.g. compile error).
if [ "$(( PASSED + FAILED + IGNORED ))" -eq 0 ]; then
  echo "could not parse any 'test result:' lines; using cargo exit code $rc" >&2
  emit_ctrf "cargo-test" 0 1 0; exit 1
fi

# A cargo failure that left no failed test (compile error) still fails the suite.
[ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ] && FAILED=1
emit_ctrf "cargo-test" "$PASSED" "$FAILED" "$IGNORED"
