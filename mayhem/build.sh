#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

PCAP_SRC="$SRC/userland/libpcap-1.10.1"
FUZZ_SRC="$PCAP_SRC/testprogs/fuzz"
# The CMake build is the vanilla libpcap (no PF_RING lib needed); the autotools build in this tree
# is wired to ../lib/libpfring.a and does not build out of tree.
CMAKE_OPTS="-DBUILD_SHARED_LIBS=OFF -DENABLE_REMOTE=OFF -DBUILD_WITH_LIBNL=OFF -DDISABLE_LINUX_USBMON=ON -DDISABLE_BLUETOOTH=ON -DDISABLE_NETMAP=ON -DDISABLE_DPDK=ON -DDISABLE_DBUS=ON -DDISABLE_RDMA=ON -DDISABLE_DAG=ON -DDISABLE_SEPTEL=ON -DDISABLE_SNF=ON -DDISABLE_TC=ON -DENABLE_PROFILING=OFF"
B_FUZZ="$SRC/mayhem/build-fuzz"
B_TEST="$SRC/mayhem/build-test"

# 1) The vendored libpcap, sanitized + SanCov-instrumented (out-of-tree; mayhem/build-fuzz is gitignored).
#    fuzzer-no-link is unconditional so the library carries coverage even when SANITIZER_FLAGS is empty.
cmake -S "$PCAP_SRC" -B "$B_FUZZ" -G "Unix Makefiles" $CMAKE_OPTS -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1" >/dev/null
cmake --build "$B_FUZZ" -j"$MAYHEM_JOBS" --target pcap_static >/dev/null
LIBPCAP_FUZZ="$(find "$B_FUZZ" -maxdepth 1 -name 'libpcap*.a' | head -n1)"

# 2) Each in-tree libpcap fuzz harness, linked twice: libFuzzer + standalone reproducer. LeakSanitizer is
#    turned off at build time via lsan_off.o.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B_FUZZ/lsan_off.o"
for h in fuzz_pcap fuzz_filter fuzz_both; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -I"$PCAP_SRC" "$FUZZ_SRC/$h.c" \
      "$B_FUZZ/lsan_off.o" "$LIBPCAP_FUZZ" -o "/mayhem/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -I"$PCAP_SRC" "$STANDALONE_FUZZ_MAIN" "$FUZZ_SRC/$h.c" \
      "$B_FUZZ/lsan_off.o" "$LIBPCAP_FUZZ" -o "/mayhem/$h-standalone"
done

# 3) The test oracle: a clean libpcap build with the project's NORMAL flags (no sanitizers, no -gdwarf-3),
#    its own filtertest, and a known-answer selftest. mayhem/test.sh only runs them.
cmake -S "$PCAP_SRC" -B "$B_TEST" -G "Unix Makefiles" $CMAKE_OPTS -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS" >/dev/null
cmake --build "$B_TEST" -j"$MAYHEM_JOBS" --target pcap_static filtertest >/dev/null
LIBPCAP_TEST="$(find "$B_TEST" -maxdepth 1 -name 'libpcap*.a' | head -n1)"
$CC -O2 $COVERAGE_FLAGS -I"$PCAP_SRC" "$SRC/mayhem/selftest.c" "$LIBPCAP_TEST" $COVERAGE_FLAGS -o "$B_TEST/selftest"
