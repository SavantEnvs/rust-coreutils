#!/usr/bin/env bash
#
# rust-coreutils/mayhem/build.sh — build a representative subset of uutils/coreutils' cargo-fuzz
# targets as sanitized libFuzzer binaries, replicating OSS-Fuzz's Rust path
# (infra/base-images/base-builder/compile + projects/rust-coreutils/build.sh, which runs
# `cargo fuzz build -O`).
#
# coreutils is a cargo workspace; the fuzz harness lives in fuzz/ as its OWN nested workspace
# ([workspace] members=["."] in fuzz/Cargo.toml). cargo-fuzz drives the build:
#   - it provides its own libFuzzer runtime (each produced binary IS a libFuzzer target — Mayhem
#     runs it directly via `libfuzzer: true`);
#   - ASan is enabled the Rust way, through RUSTFLAGS `-Zsanitizer=address` (NOT clang's
#     $SANITIZER_FLAGS / CFLAGS — those don't apply to rustc), which is exactly what OSS-Fuzz's
#     `compile` sets for FUZZING_LANGUAGE=rust. nightly is required for `-Zsanitizer`.
#
# Integrated subset (7 of the repo's 19 fuzz targets — the parser-rich utilities the task calls
# out): fuzz_printf fuzz_expr fuzz_echo fuzz_seq fuzz_test fuzz_date fuzz_split.
# Most of these are DIFFERENTIAL targets: they run the uutils implementation and compare against
# the system GNU coreutils binary of the same name (printf/expr/...). The base image ships GNU
# coreutils 9.7, so the reference binaries are present. fuzz_date is the pure data-driven one
# (it splits the input on NUL bytes into argv and runs uu_date directly).
#
# We copy each produced binary to $OUT/<target> (OUT defaults to /mayhem, the build contract).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer (kept for parity even
# though the Rust build doesn't invoke clang directly; cargo's cc-built deps might).
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SRC:=/mayhem}"
: "${OUT:=/mayhem}"
: "${MAYHEM_JOBS:=$(nproc)}"
export MAYHEM_JOBS
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

cd "$SRC"

# The cargo-fuzz crate lives in fuzz/ (cargo-fuzz convention).
FUZZ_DIR="$SRC/fuzz"
FUZZ_TARGETS=(fuzz_printf fuzz_expr fuzz_echo fuzz_seq fuzz_test fuzz_date fuzz_split)
# Targets built from mayhem/harness (its own cargo-fuzz crate) instead of fuzz/: upstream's
# fuzz_seq and fuzz_split draw their arguments (and split its input text) from the OS-seeded
# rand::rng(), so a crash is not a function of the input and cannot be replayed.
# mayhem/harness/fuzz_targets/fuzz_{seq,split}.rs decode them from the input.
HARNESS_DIR="$SRC/mayhem/harness"
HARNESS_TARGETS=(fuzz_seq fuzz_split)
is_harness_target() { local x; for x in "${HARNESS_TARGETS[@]}"; do [ "$x" = "$1" ] && return 0; done; return 1; }

# The base image exports $SANITIZER_FLAGS (clang ASan+UBSan), but those are CLANG flags and do NOT
# apply to rustc — Rust instrumentation is driven through RUSTFLAGS instead. We therefore IGNORE
# $SANITIZER_FLAGS for the rustc build and wire ASan the cargo-fuzz way below; the reference here is
# deliberate (documents why $SANITIZER_FLAGS is not forwarded to the Rust compiler).
echo "note: base \$SANITIZER_FLAGS=[${SANITIZER_FLAGS:-}] is clang-only; Rust ASan goes via RUSTFLAGS"
# via --whole-archive, placing it at .debug_info offset 0. -Zdwarf-version=3 alone does NOT win
# because the ASan runtime CU lands first. The cc-wrapper injects a DWARF3 anchor.o as the very
# first linker input, pushing the ASan runtime CU back, so readelf sees DWARF3 at offset 0.
: "${RUST_DEBUG_FLAGS:=-Cdebuginfo=2 -Zdwarf-version=3 -Clinker=/opt/mayhem-dwarf3-anchor/cc-wrapper.sh}"

# Replicate OSS-Fuzz `compile` RUSTFLAGS for a libFuzzer+ASan Rust build. cargo-fuzz sets the ASan
# flag itself by default, but we set it explicitly so the behavior is pinned and visible. `--cfg
# fuzzing` matches what libfuzzer-sys expects; force-frame-pointers aids ASan stack traces.
export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing -Zsanitizer=address -Cforce-frame-pointers ${RUST_DEBUG_FLAGS}"

echo "=== cargo fuzz build (image-default nightly toolchain, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"

# `-O` (release w/ opt) mirrors OSS-Fuzz's build.sh. cargo-fuzz reads the targets from
# fuzz/Cargo.toml. We build per-target so a single bad target doesn't mask the others, and so each
# binary path is deterministic. Use the image's DEFAULT toolchain (the Dockerfile pins it to the
# required nightly); a `+toolchain` override would make rustup try to install a different channel
# into the read-only shared /opt/rust.
for t in "${FUZZ_TARGETS[@]}"; do
  echo "--- building fuzz target: $t ---"
  if is_harness_target "$t"; then
    cargo fuzz build -O --fuzz-dir "$HARNESS_DIR" "$t"
  else
    cargo fuzz build -O --fuzz-dir "$FUZZ_DIR" "$t"
  fi
done

# Resolve the cargo-fuzz output directory via `cargo metadata` (robust against triple / workspace
# layout changes) rather than hard-coding fuzz/target/x86_64-unknown-linux-gnu. cargo-fuzz emits
# release binaries under <fuzz target_directory>/<triple>/release/<target>.
TARGET_DIR="$(cargo metadata --no-deps --format-version 1 --manifest-path "$FUZZ_DIR/Cargo.toml" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["target_directory"])')"
TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
RELDIR="$TARGET_DIR/$TRIPLE/release"
HARNESS_TARGET_DIR="$(cargo metadata --no-deps --format-version 1 --manifest-path "$HARNESS_DIR/Cargo.toml" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["target_directory"])')"
HARNESS_RELDIR="$HARNESS_TARGET_DIR/$TRIPLE/release"
echo "cargo-fuzz target_directory=$TARGET_DIR  harness target_directory=$HARNESS_TARGET_DIR  triple=$TRIPLE"

for t in "${FUZZ_TARGETS[@]}"; do
  if is_harness_target "$t"; then bin="$HARNESS_RELDIR/$t"; else bin="$RELDIR/$t"; fi
  if [ ! -x "$bin" ]; then
    echo "ERROR: expected fuzz binary not found at $bin" >&2
    exit 1
  fi
  cp "$bin" "$OUT/$t"
  echo "built $OUT/$t"
done

echo "build.sh complete:"
ls -la "${FUZZ_TARGETS[@]/#/$OUT/}" 2>&1 || true
