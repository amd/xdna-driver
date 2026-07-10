#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# shellcheck disable=SC2317
# (fail() exit 1's; the return lines after it are kept on purpose as
# in-place documentation of the "non-fatal" code path, in case we ever
# flip fail() back to accumulating-and-continuing.)
# Copyright (C) 2026, Advanced Micro Devices, Inc.
#
# xrt-smi smoke test for the amdxdna firmware-log and firmware
# event-trace (DPT) features.
#
# This is the xrt-smi-only subset of tools/test_fw_dpt.sh: every test
# here drives the feature exclusively through the xrt-smi user
# interface --
#     xrt-smi --advanced configure -d <bdf> --firmware-log ...
#     xrt-smi --advanced examine   -d <bdf> --firmware-log [--watch]
#     xrt-smi --advanced configure -d <bdf> --event-trace ...
#     xrt-smi --advanced examine   -d <bdf> --event-trace [--watch]
# -- and asserts on xrt-smi's parsed output plus the driver's dmesg
# WARNs. The debugfs-node tests (fw_log_level / fw_log_dump_to_dmesg
# nodes, dump-to-dmesg streaming, dynamic_debug tail-trace) and the
# runtime-PM and full-logging ring-wrap soak groups from the original
# are intentionally NOT ported: this script touches no debugfs path and
# never swaps firmware or reloads the driver, so it is safe to run in
# CI against a stock install.
#
# Default invocation runs both the firmware-log and firmware
# event-trace groups; pass -log to restrict to log-only or -trace to
# restrict to trace-only (the two flags are mutually exclusive).
#
# --xrt-smi is optional. If not supplied, the script auto-detects
# xrt-smi from $PATH (e.g. after `source /opt/xilinx/xrt/setup.sh`) and
# then from /opt/xilinx/xrt/bin/xrt-smi. xrt-base 2.23.0+ ships both the
# --firmware-log and --event-trace subcommands, so a stock install is
# sufficient. Pass --xrt-smi <path> only when testing a
# newer-than-installed in-tree build.
#
# The event-trace groups need a workload to make the firmware emit trace
# events; they run the shim_test case selected by SHIM_TEST_CASE
# ("multi-command preempt full ELF io test real kernel good run",
# selected by exact name; valid on aie4 and npu4) in the background.
# shim_test is resolved from --shim-test <path>, else the in-repo build
# under build/Release/bins/bin/shim_test.elf, else by name on $PATH. If it
# cannot be resolved the trace read/watch groups skip cleanly (the
# firmware-log groups do not need it -- they generate their own activity
# through configure toggles).
#
# Run as root.
#
# Usage:
#     sudo ./test/scripts/test_fw_dpt_xrt_smi.sh [-log|-trace] \
#                 [--xrt-smi <path>] [--shim-test <path>]

set -euo pipefail

# Every xrt-smi invocation uses --advanced: --firmware-log and
# --event-trace are registered as hidden/advanced OptionOptions, and
# xrt-smi only honours --advanced when XRTSMIAdvanced is set. Export it
# here so the requirement is internal to the script rather than a silent
# dependency on the operator's shell env.
export XRTSMIAdvanced=1

# ---------------------------------------------------------------------------
# Constants / globals
# ---------------------------------------------------------------------------

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shim_test is the event-trace activity generator: it drives real NPU IO
# so the firmware emits the steady stream of trace events the trace
# read/watch groups need. Resolved by shim_test_init(); the trace groups
# skip cleanly if it cannot be found.
#
# SHIM_TEST_CASE selects the workload by its exact test-case *name* rather
# than a numeric index: shim_test's get_test_case_index() matches a name
# arg exactly (test/shim_test/shim_test.cpp), and names are stable across
# builds whereas the numeric index shifts as cases are added. This case
# carries dev_filter_is_aie4_or_npu4, so it is valid on both aie4 (Medusa)
# and npu4/npu5 (Strix) -- a single workload that runs on every device
# this script targets. (shim_test itself skips it on a non-matching
# device, so no invalid-case CREATE_HWCTX/-ENODEV failures like the old
# aie2-only "Multi context IO test" index produced on aie4.)
SHIM_TEST_BIN=""
SHIM_TEST_CASE="multi-command preempt full ELF io test real kernel good run"

# Resolved by xrt_smi_init().
XRT_SMI_BIN=""
XRT_SMI_LIB=""

# A real firmware-log entry row in xrt-smi --firmware-log parsed output.
# The two firmware backends format entries differently, so match either:
#   aie2:  <u64-timestamp>  <numeric_level>:<short>  <app>  <line>  <mod> ...
#          (numeric_level 0..4, short is the lowercase enum-name; unk is
#          the fallback for an out-of-range level)
#   aie4:  [<src>] <L>: <message>        e.g.  "[H] I: Powering on AIE4 rail"
#          (src tag like H, level letter like I/W/E/D)
# The --advanced disclaimer banner matches neither, so it is filtered out
# naturally.
FW_LOG_XRTSMI_RE='(^[[:space:]]*[0-9]+[[:space:]]+[0-4]:(off|err|wrn|inf|dbg|max|unk)[[:space:]])|(^\[[A-Za-z0-9]+\][[:space:]]+[A-Za-z]+:[[:space:]])'

# xrt-smi --event-trace parsed entry rows are formatted timestamp-first
# ("%-30lu ..."), so "starts with a digit" cleanly separates real entries
# from the unconditional boilerplate (disclaimer, banner, column header),
# none of which start with a digit.
FW_TRACE_XRTSMI_RE='^[0-9]'

if [[ -t 1 ]]; then
    C_RED=$'\033[1;31m'
    C_GRN=$'\033[1;32m'
    C_YLW=$'\033[1;33m'
    C_BLU=$'\033[1;34m'
    C_RST=$'\033[0m'
else
    C_RED=""
    C_GRN=""
    C_YLW=""
    C_BLU=""
    C_RST=""
fi

PASSED=0
FAILED=0
SKIPPED=0

# Mode selector. "both" runs log + trace; "log-only" and "trace-only"
# are set by the -log / -trace CLI flags (mutually exclusive).
MODE="both"

# Resolved at runtime.
BDF=""
ACCEL_DEV=""
TMPDIR_=""

# Device family resolved by discover_device() from the PCI device id:
#   aie4 -> 1022:17f1 (npu3/npu9/npu11) or 1022:17f2 (aie4 PF)
#   aie2 -> 1022:17f0 (npu4/npu5, Strix)
# DEV_ID holds the raw 4-hex device id for diagnostics. Level-4 (DBG)
# logging is a first-class, honored level on aie4; aie2/production
# firmware caps effective verbosity at level 3.
DEV_ID=""
DEV_FAMILY=""

# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

info()  { printf '%s[INFO]%s  %s\n' "$C_BLU" "$C_RST" "$*"; }
note()  { printf '       %s\n' "$*"; }
pass()  { printf '%s[PASS]%s  %s\n' "$C_GRN" "$C_RST" "$*"; PASSED=$((PASSED + 1)); }
# Fail-fast: abort on the first failure so the cause is obvious and we do
# not run follow-on tests against an already-broken kernel. The EXIT trap
# still runs the teardown and summary so the host is left clean.
fail()  { printf '%s[FAIL]%s  %s\n' "$C_RED" "$C_RST" "$*"; FAILED=$((FAILED + 1)); exit 1; }
skip()  { printf '%s[SKIP]%s  %s\n' "$C_YLW" "$C_RST" "$*"; SKIPPED=$((SKIPPED + 1)); }
group() { printf '\n%s===== %s =====%s\n' "$C_BLU" "$*" "$C_RST"; }

# emit_snippet "label" "content" [n]
#
# Evidence printer: prints "label" as an INFO line, then up to "n" head +
# '--SNIP--' + "n" tail lines from "content" as indented notes (n
# defaults to 3). If content has <= 2n lines, prints it whole. Empty
# content prints '(snippet unavailable)'. Never trips pass/fail counters.
emit_snippet() {
    local label="$1"
    local content="$2"
    local n="${3:-3}"
    local total line

    info "${label}"
    if [[ -z "${content}" ]]; then
        info "(snippet unavailable)"
        return
    fi
    total=$(printf '%s\n' "${content}" | wc -l)
    if (( total <= 2 * n )); then
        while IFS= read -r line; do
            note "  ${line}"
        done <<<"${content}"
        return
    fi
    while IFS= read -r line; do
        note "  ${line}"
    done < <(head -n "${n}" <<<"${content}")
    note "  --SNIP--"
    while IFS= read -r line; do
        note "  ${line}"
    done < <(tail -n "${n}" <<<"${content}")
}

usage() {
    cat <<EOF
${SCRIPT_NAME} - amdxdna firmware DPT (log + event-trace) xrt-smi test

Usage:
    ${SCRIPT_NAME} [-log|-trace] [--xrt-smi <path>] [--shim-test <path>] [-h]

By default both the firmware-log and firmware event-trace groups run.
Pass -log to restrict to log-only, or -trace to restrict to trace-only
(the two flags are mutually exclusive).

Options:
    -log,   --log        Run only the firmware-log groups.
    -trace, --trace      Run only the firmware event-trace groups.
    --xrt-smi <path>     Path to an xrt-smi that supports --firmware-log /
                         --event-trace. Auto-detected from \$PATH then
                         /opt/xilinx/xrt/bin/xrt-smi if unset.
    --shim-test <path>   Path to shim_test.elf used as the event-trace
                         activity generator (case ${SHIM_TEST_CASE}).
                         Auto-detected from the in-repo build then \$PATH.
                         The trace read/watch groups skip if unresolved.
    -h,     --help       Show this help.
EOF
}
# ---------------------------------------------------------------------------
# xrt-smi resolution + invocation
# ---------------------------------------------------------------------------

# Compose the LD_LIBRARY_PATH used to invoke the resolved xrt-smi:
# PREPEND XRT_SMI_LIB to any existing LD_LIBRARY_PATH (never overwrite it,
# so caller-provided entries survive). Both the xrt_smi() wrapper and the
# xrt_smi_init() probes route through this single helper so they cannot
# drift apart.
xrt_smi_ld_path() {
    printf '%s' "${XRT_SMI_LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
}

# Resolve XRT_SMI_BIN (if --xrt-smi was not passed), derive XRT_SMI_LIB
# from its directory, and probe the binary so the tests fail fast (with a
# clean diagnostic) instead of mid-loop.
#
# Resolution order:
#   1. --xrt-smi <path>                (explicit, highest priority)
#   2. `command -v xrt-smi` on $PATH   (after `source .../setup.sh`)
#   3. /opt/xilinx/xrt/bin/xrt-smi     (stock install)
#
# Probes: --version confirms the binary loads (LD_LIBRARY_PATH ok); the
# capability probe confirms the resolved xrt-smi exposes the subcommand(s)
# the selected MODE needs, so later groups do not fail mid-loop with
# "Unrecognized arguments: --firmware-log".
xrt_smi_init() {
    if [[ -z "${XRT_SMI_BIN}" ]]; then
        if command -v xrt-smi >/dev/null 2>&1; then
            XRT_SMI_BIN=$(command -v xrt-smi)
        elif [[ -x /opt/xilinx/xrt/bin/xrt-smi ]]; then
            XRT_SMI_BIN=/opt/xilinx/xrt/bin/xrt-smi
        else
            echo "ERROR: --xrt-smi <path> is required (or install xrt-base / source setup.sh)" >&2
            exit 1
        fi
    fi
    if [[ ! -x "${XRT_SMI_BIN}" ]]; then
        echo "ERROR: xrt-smi binary not executable: ${XRT_SMI_BIN}" >&2
        exit 1
    fi

    # bin/unwrapped/xrt-smi -> lib/ resolution works for both the
    # /opt/xilinx/xrt layout and the in-tree build dir layout.
    local bin_dir
    bin_dir=$(dirname "${XRT_SMI_BIN}")
    if [[ -d "${bin_dir}/../../lib" ]]; then
        XRT_SMI_LIB=$(readlink -f "${bin_dir}/../../lib")
    elif [[ -d "${bin_dir}/../lib" ]]; then
        XRT_SMI_LIB=$(readlink -f "${bin_dir}/../lib")
    else
        echo "ERROR: cannot locate xrt lib dir relative to ${XRT_SMI_BIN}" >&2
        exit 1
    fi

    local ver
    # set -e + pipefail would abort here on a broken xrt-smi (e.g. missing
    # libs) before the empty-check below can emit the friendly diagnostic;
    # tolerate a non-zero exit so the [[ -z ]] check controls the failure.
    ver=$(LD_LIBRARY_PATH="$(xrt_smi_ld_path)" "${XRT_SMI_BIN}" --version 2>&1 \
            | awk '/Hash[[:space:]]+:/{print $3; exit}') || true
    if [[ -z "${ver}" ]]; then
        echo "ERROR: xrt-smi --version failed; check LD_LIBRARY_PATH=${XRT_SMI_LIB}" >&2
        exit 1
    fi

    # Capability probe, MODE-aware: log-only needs --firmware-log,
    # trace-only needs --event-trace, both needs both.
    local cap need_log=1 need_trace=1
    case "${MODE}" in
        log-only)   need_trace=0 ;;
        trace-only) need_log=0   ;;
    esac
    # Tolerate a non-zero exit (older xrt-smi may not accept this form) so
    # the grep capability checks below decide the outcome rather than set -e.
    cap=$(LD_LIBRARY_PATH="$(xrt_smi_ld_path)" "${XRT_SMI_BIN}" --advanced examine --help 2>&1) || true
    if (( need_log )) && ! grep -q -- '--firmware-log' <<<"${cap}"; then
        echo "ERROR: xrt-smi at ${XRT_SMI_BIN} does not support --firmware-log;" >&2
        echo "       install a newer xrt-base/xrt-npu (>= 2.23.0) or pass --xrt-smi <path>," >&2
        echo "       or pass '-trace' to skip the firmware-log groups." >&2
        exit 1
    fi
    if (( need_trace )) && ! grep -q -- '--event-trace' <<<"${cap}"; then
        echo "ERROR: xrt-smi at ${XRT_SMI_BIN} does not support --event-trace;" >&2
        echo "       install a newer xrt-base/xrt-npu (>= 2.23.0) or pass --xrt-smi <path>," >&2
        echo "       or pass '-log' to skip the event-trace groups." >&2
        exit 1
    fi

    info "xrt-smi          : ${XRT_SMI_BIN}"
    info "xrt-smi lib path : ${XRT_SMI_LIB}"
    info "xrt-smi hash     : ${ver}"
    info "xrt-smi probes   : --firmware-log=$(( need_log )) --event-trace=$(( need_trace ))"
}

# Thin wrapper to run the resolved xrt-smi with the matching
# LD_LIBRARY_PATH. Safe for foreground and backgrounded (`&`) calls.
# Call sites that need to wrap xrt-smi in timeout(1) must use the inline
# LD_LIBRARY_PATH="..." "${XRT_SMI_BIN}" form instead -- a shell function
# cannot be exec()'d by timeout.
xrt_smi() {
    LD_LIBRARY_PATH="$(xrt_smi_ld_path)" \
        "${XRT_SMI_BIN}" "$@"
}

# ---------------------------------------------------------------------------
# Firmware-log configure helpers (pure xrt-smi; no debugfs)
# ---------------------------------------------------------------------------

# Set the firmware log level via xrt-smi configure (lands at
# DRM_AMDXDNA_SET_FW_LOG_STATE). Every call is a mailbox round-trip that
# makes the firmware emit a fresh "changing logging level to N" INFO
# entry, so this doubles as the firmware-log activity generator.
fw_log_set_level() {
    local level="$1"
    xrt_smi --advanced configure -d "${BDF}" --firmware-log \
        --enable --log-level "${level}" >/dev/null 2>&1
}

# Disable firmware logging via xrt-smi configure. Idempotent.
fw_log_disable() {
    xrt_smi --advanced configure -d "${BDF}" --firmware-log --disable \
        >/dev/null 2>&1 || true
}

# Regex matching a firmware level-change confirmation line in either
# backend's parsed --firmware-log output, capturing the trailing level:
#   aie2: "... changing logging level to N"
#   aie4: "[H]  : logging level set to: N"
FW_LOG_LEVEL_CONFIRM_RE='(changing logging level to|logging level set to:?)[[:space:]]+[0-9]+'

# Regex matching the aie2/production firmware's compile-time cap notice
# emitted when a level above its build limit (3) is requested.
FW_LOG_LEVEL_CAP_RE='(compile-time logging level limit|above[^\n]*logging level limit)'

# Regex matching a DBG-severity firmware-log entry (i.e. level 4 actually
# in effect). Backend formats differ:
#   aie4: "[0] D: ..." (source tag + 'D' level letter)
#   aie2: parsed row with numeric level "4:dbg"
FW_LOG_DBG_ENTRY_RE='(^\[[A-Za-z0-9]+\][[:space:]]+D:[[:space:]])|([[:space:]]4:dbg([[:space:]]|$))'

# Watch-prime the on-demand ring tail, drain once, and echo the level
# from the MOST RECENT firmware level-change confirmation (or "" if none
# is present). The fw-log ring runs no-IRQ so the tail is only serviced
# by an active --watch poll; the short background watch below advances it
# before the oneshot drain. Using the last confirmation makes this robust
# to non-monotonic sweeps: the latest transition wins.
fw_log_confirmed_level() {
    local out="${TMPDIR_}/fw_log_confirm.out"
    local wpid
    LD_LIBRARY_PATH="${XRT_SMI_LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
        "${XRT_SMI_BIN}" --advanced examine -d "${BDF}" --firmware-log --watch \
        >/dev/null 2>/dev/null &
    wpid=$!
    sleep 1
    kill -TERM "${wpid}" 2>/dev/null || true
    wait "${wpid}" 2>/dev/null || true

    : >"${out}"
    LD_LIBRARY_PATH="${XRT_SMI_LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
        timeout 5s "${XRT_SMI_BIN}" --advanced examine -d "${BDF}" \
            --firmware-log >"${out}" 2>/dev/null || true
    grep -oE "${FW_LOG_LEVEL_CONFIRM_RE}" "${out}" 2>/dev/null \
        | tail -1 | grep -oE '[0-9]+$' || true
}

# Generate firmware-log ring activity by toggling the level between two
# distinct values. The firmware emits its level-change confirmation entry
# only on an actual level change, so the burst alternates 2 <-> 3 (rather
# than re-setting one level) to guarantee a fresh entry per iteration.
# Both 2 (WRN) and 3 (INF) are honored by every firmware build; level 4
# (DBG) is intentionally avoided here because production firmware caps at
# a compile-time limit of 3, so toggling to 4 is not a reliable way to
# force a fresh confirmation. Writes are guarded so a transient PM -EBUSY
# does not abort the caller.
fw_log_activity_burst() {
    local n="${1:-10}" i
    for (( i = 0; i < n; i++ )); do
        fw_log_set_level 2 || true
        sleep 0.05
        fw_log_set_level 3 || true
        sleep 0.05
    done
}

# ---------------------------------------------------------------------------
# Firmware event-trace configure helpers (pure xrt-smi; no debugfs)
# ---------------------------------------------------------------------------

# Return "enabled"/"disabled" from xrt-smi examine --event-trace
# --status, or "unknown" if the call fails. Only the state token goes to
# stdout.
trace_state_query() {
    local out
    if ! out=$(xrt_smi --advanced examine -d "${BDF}" --event-trace --status \
                 2>/dev/null); then
        echo "unknown"
        return 1
    fi
    grep -oE 'Event trace status: (enabled|disabled)' <<<"${out}" \
        | awk '{print $NF}' | head -n1 \
        || echo "unknown"
}

# Print the comma-separated "Event trace categories: ..." string, or ""
# if not enabled / not reported.
trace_state_query_categories() {
    local out
    if ! out=$(xrt_smi --advanced examine -d "${BDF}" --event-trace --status \
                 2>/dev/null); then
        echo ""
        return 1
    fi
    grep -E 'Event trace categories:' <<<"${out}" \
        | sed -E 's/^.*Event trace categories: //' | head -n1 \
        || true
}

# Disable event tracing. Idempotent; ignores failures so the next test
# starts from a known state.
trace_force_disable() {
    xrt_smi --advanced configure -d "${BDF}" --event-trace --disable \
        >/dev/null 2>&1 || true
    sleep 0.5
}

# ---------------------------------------------------------------------------
# shim_test resolution + invocation (event-trace activity generator)
# ---------------------------------------------------------------------------

# Resolve SHIM_TEST_BIN (if --shim-test was not passed). Search order:
#   1. --shim-test <path>                             (explicit)
#   2. <repo>/build/Release/bins/bin/shim_test.elf    (in-repo build)
#   3. `command -v shim_test.sh` on $PATH
#   4. `command -v shim_test.elf` on $PATH
# Soft precondition: if nothing resolves, SHIM_TEST_BIN stays empty and
# the trace read/watch groups skip themselves rather than failing.
shim_test_init() {
    if [[ -n "${SHIM_TEST_BIN}" ]]; then
        if [[ ! -x "${SHIM_TEST_BIN}" ]]; then
            echo "ERROR: --shim-test path not executable: ${SHIM_TEST_BIN}" >&2
            exit 1
        fi
    else
        local in_repo="${SCRIPT_DIR}/../../build/Release/bins/bin/shim_test.elf"
        if [[ -x "${in_repo}" ]]; then
            SHIM_TEST_BIN=$(readlink -f "${in_repo}")
        elif command -v shim_test.sh >/dev/null 2>&1; then
            SHIM_TEST_BIN=$(command -v shim_test.sh)
        elif command -v shim_test.elf >/dev/null 2>&1; then
            SHIM_TEST_BIN=$(command -v shim_test.elf)
        fi
    fi

    if [[ -n "${SHIM_TEST_BIN}" ]]; then
        info "shim_test        : ${SHIM_TEST_BIN}"
        info "shim_test case   : ${SHIM_TEST_CASE}"
    else
        info "shim_test not found; event-trace read/watch groups will skip."
        info "      Looked for ${SCRIPT_DIR}/../../build/Release/bins/bin/shim_test.elf"
        info "      and shim_test.sh / shim_test.elf on \$PATH; pass --shim-test <path>."
    fi
}

# Launch shim_test ${SHIM_TEST_CASE} in the background as a trace-activity
# generator. Echoes the child PID (empty on error). The caller MUST pass
# the pid to shim_test_kill_bg when done. Mirrors the env the bundled
# shim_test.sh wrapper sets up (RPATH-resolved libs via XILINX_XRT).
shim_test_run_bg() {
    local out_path="$1"
    if [[ -z "${SHIM_TEST_BIN}" ]]; then
        return 127
    fi
    : >"${out_path}"
    if [[ "${SHIM_TEST_BIN}" == *.sh ]]; then
        "${SHIM_TEST_BIN}" "${SHIM_TEST_CASE}" >>"${out_path}" 2>&1 &
    else
        (
            unset LD_LIBRARY_PATH
            export XILINX_XRT
            XILINX_XRT="$(cd -- "$(dirname -- "${SHIM_TEST_BIN}")/.." && pwd)"
            "${SHIM_TEST_BIN}" "${SHIM_TEST_CASE}" >>"${out_path}" 2>&1
        ) &
    fi
    echo "$!"
}

# Reap a background shim_test. Idempotent, tolerant of "already exited";
# escalates SIGTERM -> SIGKILL after a 5s grace window. Empty pid is a
# no-op so callers need not special-case "never started".
shim_test_kill_bg() {
    local pid="${1:-}"
    [[ -z "${pid}" ]] && return 0
    kill -TERM "${pid}" 2>/dev/null || true
    local i
    for i in 1 2 3 4 5; do
        if ! kill -0 "${pid}" 2>/dev/null; then break; fi
        sleep 1
    done
    if kill -0 "${pid}" 2>/dev/null; then
        kill -KILL "${pid}" 2>/dev/null || true
    fi
    wait "${pid}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# dmesg helpers (used for the driver-side "Unexpected jump" WARN checks)
# ---------------------------------------------------------------------------

# Emit a unique marker to /dev/kmsg and echo it; dmesg_since then prints
# everything AFTER that marker -- robust against printk-timestamp format
# variations and clock-domain drift.
#
# The marker is only usable if the write to /dev/kmsg succeeds AND the
# marker is subsequently observable via dmesg. In containerized CI either
# can fail (no /dev/kmsg write permission, or dmesg not readable). In that
# case echo an EMPTY string so callers can visibly skip() their WARN check
# instead of passing vacuously on an empty dmesg_since result. Callers
# MUST treat an empty return as "marker unavailable".
dmesg_lines() {
    local marker
    marker="testmark-$$-${RANDOM}-$(date +%s%N 2>/dev/null || date +%s)"
    # The trailing newline is REQUIRED: a /dev/kmsg write without it does
    # not get emitted as a record (the write returns success but the
    # marker never appears in dmesg), which is what silently disabled this
    # check before. A failed write must not be swallowed either: if it
    # fails, return no marker so the caller skips visibly.
    if ! printf '%s\n' "${marker}" >/dev/kmsg 2>/dev/null; then
        return 0
    fi
    # Confirm the marker actually landed and is readable before relying on
    # it (guards against silently-dropped writes and unreadable dmesg).
    local i
    for i in 1 2 3; do
        if dmesg --color=never 2>/dev/null | grep -qF "${marker}"; then
            printf '%s' "${marker}"
            return 0
        fi
        sleep 0.2
    done
    # Written but not observable -> treat as unavailable (empty).
    return 0
}

dmesg_since() {
    local mark="$1"
    # An empty mark would make awk's index() match every line and dump the
    # entire buffer (old, unrelated entries) -- refuse it so a lost marker
    # cannot turn a WARN scan into a false positive/negative.
    [[ -z "${mark}" ]] && return 0
    dmesg --color=never 2>/dev/null | awk -v m="${mark}" '
        found {print; next}
        index($0, m) > 0 {found = 1}
    '
}

# ---------------------------------------------------------------------------
# Setup / discovery / teardown
# ---------------------------------------------------------------------------

require_root() {
    if (( EUID != 0 )); then
        echo "ERROR: ${SCRIPT_NAME} must be run as root" >&2
        exit 1
    fi
}

# Discover the amdxdna device via sysfs (NOT debugfs): the PCI driver
# binding under /sys/bus/pci/drivers/amdxdna exposes the bound BDF(s),
# which is all xrt-smi -d needs. ACCEL_DEV is resolved for diagnostics.
discover_device() {
    local drv="/sys/bus/pci/drivers/amdxdna"
    if [[ ! -d "${drv}" ]]; then
        echo "ERROR: ${drv} missing; amdxdna module not loaded or PCI driver not registered." >&2
        echo "       try 'sudo modprobe amdxdna'" >&2
        exit 1
    fi

    local -a bdfs=()
    local entry
    for entry in "${drv}"/[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:*; do
        [[ -e "${entry}" ]] || continue
        bdfs+=("$(basename "${entry}")")
    done
    if (( ${#bdfs[@]} == 0 )); then
        echo "ERROR: no PCI device bound to amdxdna (driver loaded but no device claimed it)." >&2
        exit 1
    fi
    if (( ${#bdfs[@]} > 1 )); then
        info "Multiple amdxdna devices found (${bdfs[*]}); using first."
    fi
    BDF="${bdfs[0]}"

    local accel_link=""
    if [[ -d "/sys/bus/pci/devices/${BDF}/accel" ]]; then
        # shellcheck disable=SC2012  # accelN names are always alphanumeric
        accel_link=$(ls "/sys/bus/pci/devices/${BDF}/accel" 2>/dev/null | head -n1 || true)
    fi
    [[ -n "${accel_link}" ]] && ACCEL_DEV="/dev/accel/${accel_link}"

    # Derive the device family from the PCI device id (sysfs, no debugfs).
    # 17f1/17f2 -> aie4 (DBG/level-4 honored); 17f0 -> aie2 (capped at 3).
    DEV_ID=$(cat "/sys/bus/pci/devices/${BDF}/device" 2>/dev/null || echo "")
    DEV_ID=${DEV_ID#0x}
    case "${DEV_ID}" in
        17f1|17f2) DEV_FAMILY="aie4" ;;
        17f0)      DEV_FAMILY="aie2" ;;
        *)         DEV_FAMILY="unknown" ;;
    esac

    info "device       : ${BDF}"
    info "accel node   : ${ACCEL_DEV:-<none>}"
    info "device id     : 0x${DEV_ID:-????} (family: ${DEV_FAMILY})"
}

# Regex matching THIS script's own leftover xrt-smi firmware-log /
# event-trace consumers. Scope it to the discovered BDF (regex-escaped)
# so we never TERM/KILL unrelated xrt-smi processes targeting a different
# device on a shared/multi-device host; fall back to the broad pattern
# only when the BDF is not yet known. All of this script's xrt-smi
# invocations pass "-d ${BDF}", so the BDF is always present in their
# command line.
dpt_consumer_pattern() {
    if [[ -n "${BDF}" ]]; then
        printf 'xrt-smi.*%s.*--(firmware-log|event-trace)' "${BDF//./\\.}"
    else
        printf 'xrt-smi.*--(firmware-log|event-trace)'
    fi
}

# Kill leftover xrt-smi --firmware-log / --event-trace consumers (scoped
# to this device's BDF) from a previously aborted run (they pin
# /dev/accel/* fds), and report the module refcount so a stuck value is
# self-evident.
pre_flight() {
    local killed pat
    pat=$(dpt_consumer_pattern)
    killed=$(pgrep -af "${pat}" 2>/dev/null || true)
    if [[ -n "${killed}" ]]; then
        info "killing leftover xrt-smi consumers (BDF-scoped):"
        while IFS= read -r line; do
            note "  ${line}"
        done <<<"${killed}"
        pkill -TERM -f "${pat}" 2>/dev/null || true
        sleep 0.5
        pkill -KILL -f "${pat}" 2>/dev/null || true
    fi
    info "refcnt before tests: $(cat /sys/module/amdxdna/refcnt 2>/dev/null || echo '?')"
}

# EXIT/INT/TERM trap: kill any watchers we spawned, disable both DPT
# features via xrt-smi so the device is left quiescent, remove the temp
# dir, and print the summary. Preserves the triggering exit code.
teardown() {
    local rc=$?
    info "Cleaning up..."

    local pat
    pat=$(dpt_consumer_pattern)
    pkill -TERM -f "${pat}" 2>/dev/null || true
    sleep 0.3
    pkill -KILL -f "${pat}" 2>/dev/null || true

    # Best-effort: only meaningful once xrt-smi has been resolved.
    if [[ -n "${XRT_SMI_BIN}" && -n "${BDF}" ]]; then
        fw_log_disable
        trace_force_disable
    fi

    if [[ -n "${TMPDIR_}" && -d "${TMPDIR_}" ]]; then
        rm -rf "${TMPDIR_}" 2>/dev/null || true
    fi

    summary || true
    exit "${rc}"
}
# ---------------------------------------------------------------------------
# Firmware-log tests (xrt-smi interface only)
# ---------------------------------------------------------------------------

# Oneshot drain: enable logging at INFO via xrt-smi configure, generate a
# handful of level-change entries, then read the ring once with xrt-smi
# examine --firmware-log and assert the parsed output has the expected
# per-entry shape.
#
# The fw-log ring runs in no-IRQ mode ("tail updates on demand only"), so
# the ring tail is advanced by the driver's on-demand poll, which is
# driven by an active --watch consumer. A bare oneshot examine therefore
# returns an empty ring unless the tail has recently been serviced, so
# each attempt primes the ring with a short background --watch while
# generating activity, stops it, then drains once.
test_fw_log_examine_oneshot() {
    group "fw_log: examine oneshot"

    fw_log_set_level 3 || { fail "configure --firmware-log --enable failed"; return; }

    local out="${TMPDIR_}/log_oneshot.out"
    local err="${TMPDIR_}/log_oneshot.err"

    local start finish elapsed rc attempt entries wpid
    rc=0
    entries=0
    elapsed=0
    for attempt in 1 2 3; do
        # Prime the ring: a short background --watch runs the driver's
        # poll so the tail advances while we emit level-change entries.
        LD_LIBRARY_PATH="${XRT_SMI_LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
            "${XRT_SMI_BIN}" --advanced examine -d "${BDF}" --firmware-log --watch \
            >/dev/null 2>/dev/null &
        wpid=$!
        fw_log_activity_burst 3
        sleep 1
        kill -TERM "${wpid}" 2>/dev/null || true
        wait "${wpid}" 2>/dev/null || true

        : >"${out}"; : >"${err}"
        start=$(date +%s)
        rc=0
        LD_LIBRARY_PATH="${XRT_SMI_LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
            timeout 5s "${XRT_SMI_BIN}" --advanced examine -d "${BDF}" \
                --firmware-log >"${out}" 2>"${err}" || rc=$?
        finish=$(date +%s)
        elapsed=$((finish - start))
        if (( rc == 124 )); then
            fail "oneshot drain did not return within 5s (attempt ${attempt})"
            return
        elif (( rc != 0 )); then
            fail "oneshot xrt-smi examine --firmware-log failed (rc=${rc}): $(head -c 256 "${err}")"
            return
        fi
        entries=$(grep -cE "${FW_LOG_XRTSMI_RE}" "${out}" 2>/dev/null) || entries=0
        (( entries >= 1 )) && break
        sleep 1
    done

    pass "oneshot drain returned in ${elapsed}s (<=5s)"
    info "oneshot stats: parsed_entries=${entries} bytes=$(stat -c %s "${out}") attempts=${attempt}"

    if (( entries >= 1 )); then
        pass "oneshot output has recognisable FW-log shape (>=1 parsed entry)"
    else
        fail "oneshot output lacks FW-log shape (parsed_entries=${entries} after ${attempt} attempts)"
    fi

    emit_snippet "oneshot parsed xrt-smi output (head):" "$(head -n 3 "${out}" 2>/dev/null || true)" 3
    emit_snippet "oneshot parsed xrt-smi output (tail):" "$(tail -n 3 "${out}" 2>/dev/null || true)" 3
}

# Watch (streaming) mode: background a `--firmware-log --watch` consumer,
# drive activity through configure toggles, assert its capture grows,
# then confirm it exits cleanly on SIGTERM and, in a second pass, that a
# configure --disable propagates -ESHUTDOWN so the watcher exits on its
# own.
test_fw_log_examine_watch() {
    group "fw_log: examine watch"

    fw_log_set_level 3 || { fail "configure --firmware-log --enable failed"; return; }

    local out="${TMPDIR_}/log_watch.out"
    local err="${TMPDIR_}/log_watch.err"
    : >"${out}"; : >"${err}"

    xrt_smi --advanced examine -d "${BDF}" --firmware-log --watch \
        >"${out}" 2>"${err}" &
    local watcher_pid=$!
    sleep 1
    if ! kill -0 "${watcher_pid}" 2>/dev/null; then
        wait "${watcher_pid}" 2>/dev/null || true
        fail "watcher exited immediately. stderr: $(head -c 256 "${err}")"
        return
    fi
    info "watcher pid=${watcher_pid}"

    # Activity generator: configure-toggle the level in a tight loop; each
    # toggle is a mailbox round-trip that emits a fresh FW entry into the
    # ring while the watcher is blocked in wait_event.
    local activity_pid
    (
        for _ in $(seq 1 30); do
            fw_log_set_level 2 || true
            sleep 0.2
            fw_log_set_level 3 || true
            sleep 0.2
        done
    ) &
    activity_pid=$!

    local size_0 size_4 delta
    size_0=$(stat -c %s "${out}")
    sleep 4
    size_4=$(stat -c %s "${out}")
    delta=$((size_4 - size_0))

    kill -TERM "${activity_pid}" 2>/dev/null || true
    wait "${activity_pid}" 2>/dev/null || true
    fw_log_set_level 3 || true

    if (( delta >= 1024 )); then
        pass "watcher output grew (${size_0} -> ${size_4} bytes, +${delta})"
    else
        fail "watcher output did not grow >=1024 (${size_0} -> ${size_4} bytes, +${delta})"
    fi

    kill -TERM "${watcher_pid}" 2>/dev/null || true
    local i
    for i in 1 2 3 4 5; do
        if ! kill -0 "${watcher_pid}" 2>/dev/null; then break; fi
        sleep 1
    done
    if kill -0 "${watcher_pid}" 2>/dev/null; then
        kill -KILL "${watcher_pid}" 2>/dev/null || true
        wait "${watcher_pid}" 2>/dev/null || true
        fail "watcher did not exit cleanly after SIGTERM"
    else
        wait "${watcher_pid}" 2>/dev/null || true
        pass "watcher exited after SIGTERM"
    fi

    # ESHUTDOWN race: fresh watcher, then configure --disable. The kernel
    # delivers -ESHUTDOWN to the in-flight ioctl; how xrt-smi reacts is
    # backend-dependent -- on some it propagates and the process exits, on
    # others (e.g. aie4) it surfaces the "disabled during query" error and
    # keeps polling. Accept either: the watcher exits on its own, OR it
    # surfaces the ESHUTDOWN error (then we SIGTERM it).
    : >"${out}"; : >"${err}"
    xrt_smi --advanced examine -d "${BDF}" --firmware-log --watch \
        >"${out}" 2>"${err}" &
    local pid2=$!
    sleep 2
    if ! kill -0 "${pid2}" 2>/dev/null; then
        wait "${pid2}" 2>/dev/null || true
        fail "ESHUTDOWN watcher exited prematurely before disable"
        return
    fi

    fw_log_disable

    local exited=0 saw_eshutdown=0 i
    for i in 1 2 3 4 5; do
        kill -0 "${pid2}" 2>/dev/null || exited=1
        if grep -qE 'ESHUTDOWN|[Ff]irmware log disabled|[Ss]hutdown|transport endpoint shutdown' \
                "${err}" "${out}" 2>/dev/null; then
            saw_eshutdown=1
        fi
        (( exited || saw_eshutdown )) && break
        sleep 1
    done

    if (( exited )); then
        wait "${pid2}" 2>/dev/null || true
        pass "watcher exited on its own after --disable (ESHUTDOWN path)"
    elif (( saw_eshutdown )); then
        pass "watcher surfaced ESHUTDOWN / disabled-during-query after --disable (keeps polling)"
    else
        info "(watcher neither exited nor reported ESHUTDOWN; stderr tail:)"
        tail -c 256 "${err}" | sed 's/^/       /'
        fail "watcher neither exited nor reported ESHUTDOWN within 5s after --disable"
    fi

    # Clean up if the watcher kept polling (the keep-polling backend).
    if kill -0 "${pid2}" 2>/dev/null; then
        kill -TERM "${pid2}" 2>/dev/null || true
        for i in 1 2 3 4 5; do
            if ! kill -0 "${pid2}" 2>/dev/null; then break; fi
            sleep 1
        done
        kill -KILL "${pid2}" 2>/dev/null || true
        wait "${pid2}" 2>/dev/null || true
    fi

    emit_snippet "watcher capture (head, steady-state):" \
                 "$(head -n 3 "${out}" 2>/dev/null || true)" 3
    emit_snippet "watcher capture (tail, near ESHUTDOWN):" \
                 "$(tail -n 3 "${out}" 2>/dev/null || true)" 3
}

# Multi-watcher catch-up: launch three --watch consumers at staggered
# times with a configure-driven workload batch between each launch. The
# driver contract is that every watcher -- whenever it joined -- ends up
# with the SAME total set of FW-log entries (late joiners catch up from
# offset 0). Assert per-watcher non-empty capture, total-set equality
# (sort -u then cmp), and no driver "Unexpected jump in tail pointer"
# WARN. Level is held at INFO so only the workload announcements land.
test_fw_log_multi_watcher() {
    group "fw_log: multi-watcher"

    local out_A="${TMPDIR_}/log_multi_A.txt" err_A="${TMPDIR_}/log_multi_A.err"
    local out_B="${TMPDIR_}/log_multi_B.txt" err_B="${TMPDIR_}/log_multi_B.err"
    local out_C="${TMPDIR_}/log_multi_C.txt" err_C="${TMPDIR_}/log_multi_C.err"
    : >"${out_A}"; : >"${err_A}"
    : >"${out_B}"; : >"${err_B}"
    : >"${out_C}"; : >"${err_C}"

    # 10 configure --enable --log-level 3 round-trips == ~10 FW "changing
    # logging level to 3" INFO entries; well below the ring capacity so no
    # wrap-induced overrun.
    workload() { fw_log_activity_burst 10; }

    snap() {
        local label="$1" cA cB cC
        cA=$(grep -cE "${FW_LOG_XRTSMI_RE}" "${out_A}" 2>/dev/null) || cA=0
        cB=$(grep -cE "${FW_LOG_XRTSMI_RE}" "${out_B}" 2>/dev/null) || cB=0
        cC=$(grep -cE "${FW_LOG_XRTSMI_RE}" "${out_C}" 2>/dev/null) || cC=0
        info "${label}: A=${cA} B=${cB} C=${cC}"
    }

    fw_log_set_level 3 || { fail "configure --firmware-log --enable failed"; return; }

    local mark
    mark=$(dmesg_lines)

    local pid_A pid_B pid_C

    workload            # batch 0, before any watcher
    sleep 0.5

    xrt_smi --advanced examine -d "${BDF}" --firmware-log --watch \
        >"${out_A}" 2>"${err_A}" &
    pid_A=$!
    info "watcher A pid=${pid_A} launched after batch 0"
    sleep 0.5

    workload            # batch 1, only A watching
    sleep 0.5
    snap "after batch 1 (A)"

    xrt_smi --advanced examine -d "${BDF}" --firmware-log --watch \
        >"${out_B}" 2>"${err_B}" &
    pid_B=$!
    info "watcher B pid=${pid_B} launched after batch 1"
    sleep 0.5

    workload            # batch 2, A+B watching
    sleep 0.5
    snap "after batch 2 (A+B)"

    xrt_smi --advanced examine -d "${BDF}" --firmware-log --watch \
        >"${out_C}" 2>"${err_C}" &
    pid_C=$!
    info "watcher C pid=${pid_C} launched after batch 2"
    sleep 0.5

    workload            # batch 3, A+B+C watching
    sleep 1
    snap "after batch 3 (A+B+C)"

    kill "${pid_A}" "${pid_B}" "${pid_C}" 2>/dev/null || true
    wait "${pid_A}" "${pid_B}" "${pid_C}" 2>/dev/null || true
    sleep 0.2

    fw_log_set_level 3 || true

    local nA nB nC
    nA=$(grep -cE "${FW_LOG_XRTSMI_RE}" "${out_A}" 2>/dev/null) || nA=0
    nB=$(grep -cE "${FW_LOG_XRTSMI_RE}" "${out_B}" 2>/dev/null) || nB=0
    nC=$(grep -cE "${FW_LOG_XRTSMI_RE}" "${out_C}" 2>/dev/null) || nC=0
    info "multi-watcher captured: A=${nA} B=${nB} C=${nC} entries"

    local name n
    for name in A B C; do
        case "${name}" in
            A) n="${nA}" ;;
            B) n="${nB}" ;;
            C) n="${nC}" ;;
        esac
        if (( n >= 1 )); then
            pass "watcher ${name} captured ${n} FW-log entries"
        else
            fail "watcher ${name} captured ZERO FW-log entries"
        fi
    done

    local sorted_A="${TMPDIR_}/log_multi_A.sorted"
    local sorted_B="${TMPDIR_}/log_multi_B.sorted"
    local sorted_C="${TMPDIR_}/log_multi_C.sorted"
    grep -E "${FW_LOG_XRTSMI_RE}" "${out_A}" | sort -u >"${sorted_A}"
    grep -E "${FW_LOG_XRTSMI_RE}" "${out_B}" | sort -u >"${sorted_B}"
    grep -E "${FW_LOG_XRTSMI_RE}" "${out_C}" | sort -u >"${sorted_C}"

    local uniq_A
    uniq_A=$(wc -l <"${sorted_A}")
    if cmp -s "${sorted_A}" "${sorted_B}" && cmp -s "${sorted_A}" "${sorted_C}"; then
        pass "total-set equality: all 3 watchers captured identical FW-log sets"
        info "all 3 watchers captured ${uniq_A} unique FW-log entries (after dedupe)"
    else
        fail "total-set equality violated across watchers"
        emit_snippet "A vs B symmetric difference (first 10):" \
                     "$(comm -3 "${sorted_A}" "${sorted_B}" | head -n 10 || true)" 10
        emit_snippet "A vs C symmetric difference (first 10):" \
                     "$(comm -3 "${sorted_A}" "${sorted_C}" | head -n 10 || true)" 10
    fi

    if [[ -z "${mark}" ]]; then
        skip "dmesg marker unavailable (/dev/kmsg not writable or dmesg not readable);" \
             "skipping 'Unexpected jump in tail pointer' WARN check to avoid a vacuous pass"
    else
        local jump
        jump=$(dmesg_since "${mark}" | grep "Unexpected jump in tail pointer" || true)
        if [[ -z "${jump}" ]]; then
            pass "no 'Unexpected jump in tail pointer' WARN during multi-watcher group"
        else
            fail "'Unexpected jump in tail pointer' WARN during multi-watcher group:"
            while IFS= read -r line; do note "  ${line}"; done <<<"${jump}"
        fi
    fi
}

# Level sweep with firmware-confirmed validation. For each transition the
# assertion is not "configure returned 0" but "the firmware's own log,
# read back via xrt-smi examine --firmware-log, confirms it is now at
# level N" (fw_log_confirmed_level parses the most-recent confirmation).
#
# The valid level range is backend-dependent: aie4 honors DBG (level 4)
# as a first-class level, so its sweep includes 4; aie2/production caps
# effective verbosity at 3, so its sweep stays 1..3 (level 4 is covered by
# test_fw_log_level4). Level 0 (OFF) is rejected by the driver's configure
# path on both. Each backend runs a monotonic walk and a non-monotonic
# sequence so both increasing and decreasing transitions are validated.
test_fw_log_level_sweep() {
    group "fw_log: level sweep (FW-confirmed, ${DEV_FAMILY})"

    local seq_mono seq_nonmono
    if [[ "${DEV_FAMILY}" == "aie4" ]]; then
        seq_mono="1 2 3 4"
        seq_nonmono="1 4 2 3"
    else
        seq_mono="1 2 3"
        seq_nonmono="1 2 1 3"
    fi
    info "sweep levels for ${DEV_FAMILY}: mono='${seq_mono}' nonmono='${seq_nonmono}'"

    local seqname seq target got
    for seqname in mono nonmono; do
        if [[ "${seqname}" == "mono" ]]; then
            seq="${seq_mono}"
        else
            seq="${seq_nonmono}"
        fi
        info "sweep (${seqname}): ${seq}"
        for target in ${seq}; do
            if ! fw_log_set_level "${target}"; then
                fail "[${seqname}] configure --firmware-log --enable --log-level ${target} failed"
                continue
            fi
            got=$(fw_log_confirmed_level)
            if [[ "${got}" == "${target}" ]]; then
                pass "[${seqname}] FW confirmed level ${target} (log reports level ${got})"
            else
                fail "[${seqname}] FW did not confirm level ${target} (last confirmed level='${got:-none}')"
            fi
        done
    done
}

# Backend-aware level-4 (DBG) behavior. This is a deterministic
# per-backend expectation, not an "accept whichever" classification:
#   - aie4:            level 4 IS honored. Assert the FW confirms level 4,
#                      DBG-severity entries appear, and NO compile-time cap
#                      notice is present. Fail if level 4 is not honored.
#   - aie2/production: level 4 is NOT effective. Assert the compile-time
#                      cap notice is present and no DBG entries appear.
#                      Fail if level 4 unexpectedly takes effect.
# configure --log-level 4 returns 0 on both (the driver accepts 1..4); the
# difference is purely in the firmware's effective behavior. The prior
# level is restored to a valid (<=3) value afterwards.
test_fw_log_level4() {
    group "fw_log: level 4 / DBG (${DEV_FAMILY} expectation)"

    # Known-good baseline so the "prior level" is a confirmed 3.
    fw_log_set_level 3 || { fail "baseline configure --log-level 3 failed"; return; }
    local base
    base=$(fw_log_confirmed_level)
    if [[ "${base}" == "3" ]]; then
        pass "baseline FW-confirmed at level 3 before level-4 attempt"
    else
        fail "baseline level not confirmed as 3 (got '${base:-none}')"
    fi

    # configure --log-level 4 is accepted by the driver on both backends.
    local rc=0
    xrt_smi --advanced configure -d "${BDF}" --firmware-log \
        --enable --log-level 4 >/dev/null 2>&1 || rc=$?
    if (( rc == 0 )); then
        pass "configure --firmware-log --enable --log-level 4 returned 0 (accepted by driver)"
    else
        fail "configure --log-level 4 returned ${rc} (expected 0; driver accepts 1..4)"
    fi

    # Generate a little more runtime-config traffic while (nominally) at
    # level 4: on aie4 these are processed at DBG and emit "[0] D:" echoes,
    # giving a deterministic DBG signal. Harmless on aie2 (capped at 3, so
    # no DBG entry is produced regardless).
    local i
    for i in 1 2 3; do
        fw_log_set_level 4 || true
        sleep 0.1
    done

    # Drain the firmware log (watch-primed).
    local out="${TMPDIR_}/log_level4.out"
    local wpid
    LD_LIBRARY_PATH="${XRT_SMI_LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
        "${XRT_SMI_BIN}" --advanced examine -d "${BDF}" --firmware-log --watch \
        >/dev/null 2>/dev/null &
    wpid=$!
    sleep 1
    kill -TERM "${wpid}" 2>/dev/null || true
    wait "${wpid}" 2>/dev/null || true
    : >"${out}"
    LD_LIBRARY_PATH="${XRT_SMI_LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
        timeout 5s "${XRT_SMI_BIN}" --advanced examine -d "${BDF}" \
            --firmware-log >"${out}" 2>/dev/null || true

    local capped confirmed4 dbg
    capped=$(grep -icE "${FW_LOG_LEVEL_CAP_RE}" "${out}" 2>/dev/null) || capped=0
    confirmed4=$(grep -oE "${FW_LOG_LEVEL_CONFIRM_RE}" "${out}" 2>/dev/null \
        | grep -cE '[[:space:]]4$') || confirmed4=0
    dbg=$(grep -cE "${FW_LOG_DBG_ENTRY_RE}" "${out}" 2>/dev/null) || dbg=0
    info "level-4 signals (${DEV_FAMILY}): cap_notice=${capped} confirmed_level4=${confirmed4} dbg_entries=${dbg}"

    case "${DEV_FAMILY}" in
    aie4)
        if (( capped == 0 )); then
            pass "no compile-time cap notice (aie4 honors DBG)"
        else
            fail "unexpected compile-time cap notice on aie4 (level 4 must be honored)"
            emit_snippet "unexpected cap notice:" \
                         "$(grep -iE "${FW_LOG_LEVEL_CAP_RE}" "${out}" | head -n 2 || true)" 2
        fi
        if (( confirmed4 > 0 )); then
            pass "FW confirmed level 4 (DBG)"
        else
            fail "FW did not confirm level 4 on aie4"
        fi
        if (( dbg > 0 )); then
            pass "DBG-severity entries present at level 4 (${dbg} entries)"
            emit_snippet "DBG entries:" \
                         "$(grep -E "${FW_LOG_DBG_ENTRY_RE}" "${out}" | head -n 3 || true)" 3
        else
            fail "no DBG-severity entries at level 4 on aie4 (DBG expected to be honored)"
        fi
        ;;
    aie2)
        if (( capped > 0 )); then
            pass "level 4 capped at 3: FW compile-time cap notice present (aie2/production)"
            emit_snippet "FW cap notice:" \
                         "$(grep -iE "${FW_LOG_LEVEL_CAP_RE}" "${out}" | head -n 2 || true)" 2
        else
            fail "expected compile-time cap notice on aie2; level 4 must not take effect"
        fi
        if (( dbg == 0 )); then
            pass "no DBG-severity entries: level 4 did not take effect (aie2)"
        else
            fail "unexpected DBG-severity entries on aie2 (${dbg}); level 4 should be capped at 3"
        fi
        ;;
    *)
        info "unknown device family '${DEV_FAMILY}'; reporting observed level-4 behavior without a fixed expectation"
        if (( capped > 0 || confirmed4 > 0 )); then
            pass "level 4 exercised (cap_notice=${capped}, confirmed_level4=${confirmed4}, dbg=${dbg})"
        else
            fail "level 4 neither capped nor confirmed by FW (unexpected)"
            emit_snippet "raw --firmware-log output (tail):" "$(tail -n 5 "${out}" 2>/dev/null || true)" 5
        fi
        ;;
    esac

    # Restore a valid, honored level for any subsequent groups.
    fw_log_set_level 3 || true
}
# ---------------------------------------------------------------------------
# Firmware event-trace tests (xrt-smi interface only)
#
# The trace path reuses the DPT framework but has no debugfs nodes: state
# is driven by configure --event-trace --enable/--disable and read back
# by examine --event-trace --status. The binary trace payload is decoded
# by the xrt-smi parser; the tests treat a parsed entry as any
# timestamp-leading row and otherwise assert on return codes and status.
# shim_test provides the IO workload the firmware traces.
# ---------------------------------------------------------------------------

# Enable/disable state machine + category selection, all through xrt-smi.
test_fw_trace_enable_disable() {
    group "fw_trace: enable/disable"

    local rc state cats

    trace_force_disable
    state=$(trace_state_query)
    if [[ "${state}" == "disabled" ]]; then
        pass "initial state: disabled"
    else
        fail "initial state: ${state} (expected disabled)"
    fi

    rc=0
    xrt_smi --advanced configure -d "${BDF}" --event-trace --enable \
            --categories all >/dev/null 2>&1 || rc=$?
    if (( rc == 0 )); then
        pass "configure --enable --categories all returned 0"
    else
        fail "configure --enable --categories all returned ${rc}"
    fi

    state=$(trace_state_query)
    if [[ "${state}" == "enabled" ]]; then
        pass "state after --enable: enabled"
    else
        fail "state after --enable: ${state} (expected enabled)"
    fi

    cats=$(trace_state_query_categories)
    if [[ -n "${cats}" && "${cats}" != "none" ]]; then
        pass "categories after --enable: ${cats}"
    else
        fail "categories after --enable: '${cats}' (expected non-empty)"
    fi

    # Narrow-mask reconfigure using the first name from --list-categories.
    local first_cat
    # Tolerate a non-zero exit (older xrt-smi lacks --list-categories) so an
    # empty first_cat drives the clean skip below instead of set -e aborting.
    first_cat=$(xrt_smi --advanced configure -d "${BDF}" --event-trace \
            --list-categories 2>/dev/null \
            | awk '/^Available event trace categories/{flag=1; next}
                   flag && /^[[:space:]]+[A-Za-z_][A-Za-z0-9_]*$/{print $1; exit}') || true
    if [[ -n "${first_cat}" ]]; then
        info "narrow-mask test will use category: ${first_cat}"
        rc=0
        xrt_smi --advanced configure -d "${BDF}" --event-trace --enable \
                --categories "${first_cat}" >/dev/null 2>&1 || rc=$?
        if (( rc == 0 )); then
            pass "configure --enable --categories ${first_cat} returned 0"
        else
            fail "configure --enable --categories ${first_cat} returned ${rc}"
        fi
        cats=$(trace_state_query_categories)
        if grep -q "${first_cat}" <<<"${cats}"; then
            pass "categories readback contains '${first_cat}': ${cats}"
        else
            fail "categories readback missing '${first_cat}': ${cats}"
        fi
    else
        skip "no categories exposed by xrt-smi --list-categories"
    fi

    rc=0
    xrt_smi --advanced configure -d "${BDF}" --event-trace --disable \
        >/dev/null 2>&1 || rc=$?
    if (( rc == 0 )); then
        pass "configure --disable returned 0"
    else
        fail "configure --disable returned ${rc}"
    fi
    state=$(trace_state_query)
    if [[ "${state}" == "disabled" ]]; then
        pass "state after --disable: disabled"
    else
        fail "state after --disable: ${state} (expected disabled)"
    fi
}

# Oneshot drain of the trace ring while shim_test drives IO in the
# background. Asserts the read returns within 5s and yields >=1 parsed
# entry row.
test_fw_trace_examine_oneshot() {
    group "fw_trace: examine oneshot"

    if [[ -z "${SHIM_TEST_BIN}" ]]; then
        skip "shim_test not resolved; trace ring stays empty (pass --shim-test <path>)"
        return
    fi

    trace_force_disable
    xrt_smi --advanced configure -d "${BDF}" --event-trace --enable \
            --categories all >/dev/null 2>&1 || true

    local out="${TMPDIR_}/trace_oneshot.out"
    local err="${TMPDIR_}/trace_oneshot.err"
    local activity_log="${TMPDIR_}/trace_oneshot_activity.log"
    local activity_pid
    activity_pid=$(shim_test_run_bg "${activity_log}")
    info "trace activity: shim_test ${SHIM_TEST_CASE} pid=${activity_pid}"
    sleep 1

    # Like fw-log on aie4, the trace ring tail is serviced on demand by an
    # active --watch poll (no-IRQ mode), so a bare oneshot reads empty even
    # while a workload drives events. Each attempt runs a short background
    # --watch to prime the tail while shim_test generates NPU IO, stops it,
    # then drains once. shim_test is relaunched if it finished, so the ring
    # keeps being fed. Each drain must still return within 5s (no hang).
    local start finish elapsed rc attempt bytes entries wpid
    rc=0
    entries=0
    elapsed=0
    for attempt in 1 2 3 4 5 6; do
        # Keep the workload feeding the ring.
        if ! kill -0 "${activity_pid}" 2>/dev/null; then
            shim_test_kill_bg "${activity_pid}"
            activity_pid=$(shim_test_run_bg "${activity_log}")
        fi
        # Prime the on-demand ring tail with a short background watch.
        LD_LIBRARY_PATH="${XRT_SMI_LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
            "${XRT_SMI_BIN}" --advanced examine -d "${BDF}" --event-trace --watch \
            >/dev/null 2>/dev/null &
        wpid=$!
        sleep 2
        kill -TERM "${wpid}" 2>/dev/null || true
        wait "${wpid}" 2>/dev/null || true

        : >"${out}"; : >"${err}"
        start=$(date +%s)
        rc=0
        LD_LIBRARY_PATH="${XRT_SMI_LIB}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
            timeout 5s "${XRT_SMI_BIN}" --advanced examine -d "${BDF}" \
                --event-trace >"${out}" 2>"${err}" || rc=$?
        finish=$(date +%s)
        elapsed=$((finish - start))
        if (( rc == 124 )); then
            shim_test_kill_bg "${activity_pid}"
            fail "oneshot drain did not return within 5s (attempt ${attempt})"
            trace_force_disable
            return
        elif (( rc != 0 )); then
            shim_test_kill_bg "${activity_pid}"
            fail "oneshot xrt-smi examine --event-trace failed (rc=${rc}): $(head -c 256 "${err}")"
            trace_force_disable
            return
        fi
        entries=$(grep -cE "${FW_TRACE_XRTSMI_RE}" "${out}" 2>/dev/null) || entries=0
        (( entries >= 1 )) && break
        sleep 1
    done

    shim_test_kill_bg "${activity_pid}"

    pass "oneshot drain returned in ${elapsed}s (<=5s)"

    bytes=$(stat -c %s "${out}" 2>/dev/null || echo 0)
    info "oneshot stats: bytes=${bytes} entries=${entries} attempts=${attempt}"

    if (( entries >= 1 )); then
        pass "oneshot captured ${entries} parsed trace entries"
        emit_snippet "oneshot parsed trace entries (head):" \
                     "$(grep -E "${FW_TRACE_XRTSMI_RE}" "${out}" | head -n 5 || true)" 5
        emit_snippet "oneshot parsed trace entries (tail):" \
                     "$(grep -E "${FW_TRACE_XRTSMI_RE}" "${out}" | tail -n 5 || true)" 5
    else
        emit_snippet "shim_test activity (head):" "$(head -n 20 "${activity_log}" 2>/dev/null || true)" 20
        emit_snippet "shim_test activity (tail):" "$(tail -n 20 "${activity_log}" 2>/dev/null || true)" 20
        fail "oneshot captured 0 parsed trace entries (${bytes} bytes of boilerplate) after" \
             "${attempt} drain attempts during shim_test ${SHIM_TEST_CASE} activity;" \
             "FW emitted no recognised trace events"
    fi

    trace_force_disable
}

# Watch (streaming) mode with shim_test as activity generator. Asserts
# the watcher captures >=1 parsed entry, exits on SIGTERM, and that a
# configure --disable propagates -ESHUTDOWN to the in-flight ioctl.
test_fw_trace_examine_watch() {
    group "fw_trace: examine watch"

    if [[ -z "${SHIM_TEST_BIN}" ]]; then
        skip "shim_test not resolved; trace ring stays empty (pass --shim-test <path>)"
        return
    fi

    trace_force_disable
    xrt_smi --advanced configure -d "${BDF}" --event-trace --enable \
            --categories all >/dev/null 2>&1 || true

    local out="${TMPDIR_}/trace_watch.out"
    local err="${TMPDIR_}/trace_watch.err"
    : >"${out}"; : >"${err}"

    xrt_smi --advanced examine -d "${BDF}" --event-trace --watch \
        >"${out}" 2>"${err}" &
    local watcher_pid=$!
    sleep 1
    if ! kill -0 "${watcher_pid}" 2>/dev/null; then
        wait "${watcher_pid}" 2>/dev/null || true
        fail "trace watcher exited immediately. stderr: $(head -c 256 "${err}")"
        trace_force_disable
        return
    fi
    info "trace watcher pid=${watcher_pid}"

    local activity_log="${TMPDIR_}/trace_watch_activity.log"
    local activity_pid
    activity_pid=$(shim_test_run_bg "${activity_log}")
    info "trace activity: shim_test ${SHIM_TEST_CASE} pid=${activity_pid}"

    local size_0 size_4 delta
    size_0=$(stat -c %s "${out}")
    sleep 4
    size_4=$(stat -c %s "${out}")
    delta=$((size_4 - size_0))

    shim_test_kill_bg "${activity_pid}"

    kill -TERM "${watcher_pid}" 2>/dev/null || true
    local i
    for i in 1 2 3 4 5; do
        if ! kill -0 "${watcher_pid}" 2>/dev/null; then break; fi
        sleep 1
    done
    if kill -0 "${watcher_pid}" 2>/dev/null; then
        kill -KILL "${watcher_pid}" 2>/dev/null || true
        wait "${watcher_pid}" 2>/dev/null || true
        fail "trace watcher did not exit cleanly after SIGTERM"
    else
        wait "${watcher_pid}" 2>/dev/null || true
        pass "trace watcher exited after SIGTERM"
    fi
    sleep 0.2

    local entries
    entries=$(grep -cE "${FW_TRACE_XRTSMI_RE}" "${out}" 2>/dev/null) || entries=0
    if (( entries >= 1 )); then
        pass "trace watcher captured ${entries} parsed entries (${size_0} -> ${size_4} bytes, +${delta})"
    else
        emit_snippet "shim_test activity (head):" "$(head -n 20 "${activity_log}" 2>/dev/null || true)" 20
        emit_snippet "shim_test activity (tail):" "$(tail -n 20 "${activity_log}" 2>/dev/null || true)" 20
        fail "trace watcher captured 0 parsed entries after 4s of shim_test ${SHIM_TEST_CASE} activity"
    fi

    # ESHUTDOWN race: fresh watcher, then --disable; the kernel must
    # deliver -ESHUTDOWN to the in-flight ioctl. The event-trace watch
    # loop keeps polling (unlike firmware-log), so we assert the error
    # message surfaces, not that the process exits on its own.
    : >"${out}"; : >"${err}"
    xrt_smi --advanced examine -d "${BDF}" --event-trace --watch \
        >"${out}" 2>"${err}" &
    local pid2=$!
    sleep 2
    if ! kill -0 "${pid2}" 2>/dev/null; then
        wait "${pid2}" 2>/dev/null || true
        fail "ESHUTDOWN trace watcher exited prematurely before disable"
        trace_force_disable
        return
    fi

    xrt_smi --advanced configure -d "${BDF}" --event-trace --disable \
        >/dev/null 2>&1 || true

    local saw_eshutdown=0
    for i in 1 2 3 4 5; do
        if grep -qE 'ESHUTDOWN|[Ee]vent trace disabled|[Ff]irmware.*disabled|[Ss]hutdown|Cannot send after transport endpoint shutdown' \
                "${err}" "${out}" 2>/dev/null; then
            saw_eshutdown=1
            break
        fi
        sleep 1
    done
    if (( saw_eshutdown )); then
        pass "kernel delivered -ESHUTDOWN to in-flight watcher ioctl after --disable"
    else
        fail "no ESHUTDOWN-derived error in watcher output within 5s after --disable"
        info "stderr tail:"
        tail -c 256 "${err}" | sed 's/^/       /'
    fi

    kill -TERM "${pid2}" 2>/dev/null || true
    for i in 1 2 3 4 5; do
        if ! kill -0 "${pid2}" 2>/dev/null; then break; fi
        sleep 1
    done
    if kill -0 "${pid2}" 2>/dev/null; then
        kill -KILL "${pid2}" 2>/dev/null || true
    fi
    wait "${pid2}" 2>/dev/null || true
    pass "trace watcher cleaned up via SIGTERM after ESHUTDOWN"

    trace_force_disable
}

# Multi-watcher total-set equality for trace, mirroring the firmware-log
# case but with shim_test driving the activity all three watchers see.
test_fw_trace_multi_watcher() {
    group "fw_trace: multi-watcher"

    if [[ -z "${SHIM_TEST_BIN}" ]]; then
        skip "shim_test not resolved; set-equality is trivial on empty output (pass --shim-test <path>)"
        return
    fi

    trace_force_disable
    xrt_smi --advanced configure -d "${BDF}" --event-trace --enable \
            --categories all >/dev/null 2>&1 || true

    local mark
    mark=$(dmesg_lines)

    local out_A="${TMPDIR_}/trace_multi_A.txt" err_A="${TMPDIR_}/trace_multi_A.err"
    local out_B="${TMPDIR_}/trace_multi_B.txt" err_B="${TMPDIR_}/trace_multi_B.err"
    local out_C="${TMPDIR_}/trace_multi_C.txt" err_C="${TMPDIR_}/trace_multi_C.err"
    : >"${out_A}"; : >"${err_A}"
    : >"${out_B}"; : >"${err_B}"
    : >"${out_C}"; : >"${err_C}"

    local pid_A pid_B pid_C
    xrt_smi --advanced examine -d "${BDF}" --event-trace --watch >"${out_A}" 2>"${err_A}" &
    pid_A=$!
    info "trace watcher A pid=${pid_A}"
    sleep 0.5
    xrt_smi --advanced examine -d "${BDF}" --event-trace --watch >"${out_B}" 2>"${err_B}" &
    pid_B=$!
    info "trace watcher B pid=${pid_B}"
    sleep 0.5
    xrt_smi --advanced examine -d "${BDF}" --event-trace --watch >"${out_C}" 2>"${err_C}" &
    pid_C=$!
    info "trace watcher C pid=${pid_C}"

    local activity_log="${TMPDIR_}/trace_multi_activity.log"
    local activity_pid
    activity_pid=$(shim_test_run_bg "${activity_log}")
    info "trace activity: shim_test ${SHIM_TEST_CASE} pid=${activity_pid}"

    sleep 4
    shim_test_kill_bg "${activity_pid}"
    sleep 1

    kill "${pid_A}" "${pid_B}" "${pid_C}" 2>/dev/null || true
    wait "${pid_A}" "${pid_B}" "${pid_C}" 2>/dev/null || true
    sleep 0.2

    local nA nB nC
    nA=$(grep -cE "${FW_TRACE_XRTSMI_RE}" "${out_A}" 2>/dev/null) || nA=0
    nB=$(grep -cE "${FW_TRACE_XRTSMI_RE}" "${out_B}" 2>/dev/null) || nB=0
    nC=$(grep -cE "${FW_TRACE_XRTSMI_RE}" "${out_C}" 2>/dev/null) || nC=0
    info "multi-trace-watcher captured: A=${nA} B=${nB} C=${nC} entries"

    local name n
    for name in A B C; do
        case "${name}" in
            A) n="${nA}" ;;
            B) n="${nB}" ;;
            C) n="${nC}" ;;
        esac
        if (( n >= 1 )); then
            pass "trace watcher ${name} captured ${n} parsed entries"
        else
            fail "trace watcher ${name} captured 0 parsed entries during shim_test activity"
        fi
    done

    local sorted_A="${TMPDIR_}/trace_multi_A.sorted"
    local sorted_B="${TMPDIR_}/trace_multi_B.sorted"
    local sorted_C="${TMPDIR_}/trace_multi_C.sorted"
    grep -E "${FW_TRACE_XRTSMI_RE}" "${out_A}" 2>/dev/null | sort -u >"${sorted_A}" || true
    grep -E "${FW_TRACE_XRTSMI_RE}" "${out_B}" 2>/dev/null | sort -u >"${sorted_B}" || true
    grep -E "${FW_TRACE_XRTSMI_RE}" "${out_C}" 2>/dev/null | sort -u >"${sorted_C}" || true

    local uA
    uA=$(wc -l <"${sorted_A}")
    if cmp -s "${sorted_A}" "${sorted_B}" && cmp -s "${sorted_A}" "${sorted_C}"; then
        pass "total-set equality: all 3 trace watchers captured identical sets of ${uA} unique entries"
    else
        fail "total-set equality violated for trace watchers"
        emit_snippet "A vs B symmetric difference (first 10):" \
                     "$(comm -3 "${sorted_A}" "${sorted_B}" | head -n 10 || true)" 10
        emit_snippet "A vs C symmetric difference (first 10):" \
                     "$(comm -3 "${sorted_A}" "${sorted_C}" | head -n 10 || true)" 10
    fi

    if [[ -z "${mark}" ]]; then
        skip "dmesg marker unavailable (/dev/kmsg not writable or dmesg not readable);" \
             "skipping 'Unexpected jump in tail pointer' WARN check to avoid a vacuous pass"
    else
        local jump
        jump=$(dmesg_since "${mark}" | grep "Unexpected jump in tail pointer" || true)
        if [[ -z "${jump}" ]]; then
            pass "no 'Unexpected jump in tail pointer' WARN during trace multi-watcher group"
        else
            fail "'Unexpected jump in tail pointer' WARN during trace multi-watcher group:"
            while IFS= read -r line; do note "  ${line}"; done <<<"${jump}"
        fi
    fi

    trace_force_disable
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

summary() {
    local rc
    if (( FAILED > 0 )); then rc=1; else rc=0; fi
    printf '\n%s====== FW DPT (xrt-smi) test summary ======%s\n' "$C_BLU" "$C_RST"
    printf '%spassed:%s  %d\n'  "${C_GRN}" "${C_RST}" "${PASSED}"
    printf '%sfailed:%s  %d\n'  "${C_RED}" "${C_RST}" "${FAILED}"
    printf '%sskipped:%s %d\n'  "${C_YLW}" "${C_RST}" "${SKIPPED}"
    printf '%s===========================================%s\n' "$C_BLU" "$C_RST"
    return "${rc}"
}

# ---------------------------------------------------------------------------
# Main / dispatcher
# ---------------------------------------------------------------------------

main() {
    need_arg() {
        local name="$1" val="${2-}"
        if [[ -z "${val}" || "${val:0:1}" == "-" ]]; then
            echo "Missing argument for ${name}" >&2
            usage
            exit 1
        fi
    }

    local log_flag=0 trace_flag=0

    while (( $# )); do
        case "$1" in
            -log|--log)     log_flag=1 ;;
            -trace|--trace) trace_flag=1 ;;
            --xrt-smi)   need_arg --xrt-smi "${2-}";   XRT_SMI_BIN="$2";   shift ;;
            --shim-test) need_arg --shim-test "${2-}"; SHIM_TEST_BIN="$2"; shift ;;
            -h|--help)   usage; exit 0 ;;
            *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
        esac
        shift
    done

    if (( log_flag && trace_flag )); then
        echo "ERROR: -log and -trace are mutually exclusive" >&2
        exit 1
    fi
    if (( log_flag )); then
        MODE="log-only"
    elif (( trace_flag )); then
        MODE="trace-only"
    fi

    require_root
    discover_device
    xrt_smi_init
    shim_test_init

    TMPDIR_="$(mktemp -d -t fw-dpt-xrt-smi.XXXXXX)"
    trap teardown EXIT INT TERM

    pre_flight

    if [[ "${MODE}" != "trace-only" ]]; then
        test_fw_log_examine_oneshot
        test_fw_log_examine_watch
        test_fw_log_multi_watcher
        test_fw_log_level_sweep
        test_fw_log_level4
    fi

    if [[ "${MODE}" != "log-only" ]]; then
        test_fw_trace_enable_disable
        test_fw_trace_examine_oneshot
        test_fw_trace_examine_watch
        test_fw_trace_multi_watcher
    fi
}

main "$@"
