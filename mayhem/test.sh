#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

B_TEST="$SRC/mayhem/build-test"
EXP="$SRC/mayhem/expected"
for b in "$B_TEST/selftest" "$B_TEST/run/filtertest"; do
  [ -x "$b" ] || { echo "missing $b — mayhem/build.sh should have built it" >&2; emit_ctrf "libpcap-known-answer" 0 1; exit 1; }
done

work="$(mktemp -d "${TMPDIR:-/tmp}/pf_ring-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
passed=0 failed=0

# 1) selftest: write a pcap, read it back, run BPF filters over it — every expected line must appear verbatim.
"$B_TEST/selftest" "$work/selftest.pcap" > "$work/selftest.out" 2>&1 || true
while IFS= read -r line; do
  if grep -Fxq -- "$line" "$work/selftest.out"; then passed=$((passed+1)); else failed=$((failed+1)); echo "FAIL selftest: expected '$line'" >&2; fi
done < "$EXP/selftest.txt"

# 2) filtertest: the compiled BPF program for an expression must match the golden dump exactly.
check_filter() {  # <dlt> <expression> <golden>
  "$B_TEST/run/filtertest" -d "$1" "$2" > "$work/f.out" 2>&1 || true
  if diff -u "$EXP/$3" "$work/f.out" >&2; then passed=$((passed+1)); else failed=$((failed+1)); echo "FAIL filtertest: $2" >&2; fi
}
check_filter EN10MB "tcp port 80" filter_tcp_port_80.txt
check_filter EN10MB "ip and (udp or icmp) and not host 10.0.0.9" filter_ip_udp_icmp.txt
check_filter RAW "ip proto 6" filter_raw_ip_proto6.txt

emit_ctrf "libpcap-known-answer" "$passed" "$failed" 0
