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
# One group -- "fw_dpt: cross-channel teardown" -- needs BOTH channels active at
# the same time, so it runs only in the default (both) mode and is skipped
# by -log and -trace. It is the regression test for the cross-channel SRCU
# deadlock, and on a driver that still carries that bug it will briefly
# wedge the device before recovering it by killing the readers parked in
# the DPT watch path. See the block comment above
# test_fw_dpt_cross_channel_teardown.
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

# DPT configuration as found on the device, captured by save_dpt_state()
# before anything here perturbs it and replayed by restore_dpt_state()
# from the exit trap. The tests enable, disable and re-level both
# features freely, so without this the device would be left disabled at
# level 0 no matter how the operator had it set up.
#
# The two features are tracked independently: they are restored only if
# they were captured, and they are captured only if the selected MODE
# actually runs tests against them. That keeps a -log run from touching
# event-trace at all, and keeps an unreadable status on one feature from
# costing the other its restore.
#
# A _CAPTURED flag stays 0 when the pre-run state could not be read
# completely enough to replay it. Leaving that feature alone is the safe
# choice: the tests end with both features enabled, so declining to touch
# it preserves the operator's enabled state, whereas guessing at a level
# or a category list would not.
ORIG_LOG_CAPTURED=0
ORIG_LOG_STATE=""
ORIG_LOG_LEVEL=""
ORIG_TRACE_CAPTURED=0
ORIG_TRACE_STATE=""
ORIG_TRACE_CATS=""

# ---------------------------------------------------------------------------
# Cross-channel teardown group state
# ---------------------------------------------------------------------------

# Pid this script launched a deliberately-parked watcher under. This is
# the ROOT of the watcher's process tree, which is not necessarily the
# process that blocks inside the driver's wait_event_interruptible -- see
# dpt_watcher_tree. On a driver with the cross-channel SRCU bug that parked
# reader is the ONLY thing whose death lets a blocked
# amdxdna_dpt_fini_chan() finish, so the EXIT/INT/TERM trap must always
# release it: an interrupted run that leaves it behind leaves the device
# wedged until somebody kills that reader by hand.
DPT_PARKED_WATCHER_PID=""

# Pid of the backgrounded, timed "configure --disable" under measurement.
DPT_DISABLE_PID=""

# Set to 1 once a teardown has been seen NOT to return even after every
# reader found parked in the DPT watch path was released. It records an
# observation, not a verdict on the host: teardown() re-checks whether the
# device answers once its own cleanup has run, and only skips the DPT
# state restore if it does not, because the configure ioctls that replay
# the captured state would block on the dev_lock a still-blocked teardown
# holds.
DPT_DEVICE_WEDGED=0

# Wall-clock budget for a DPT disable issued while a watcher is parked.
# The verified-good figures on aie4 are ~200ms cross-channel and ~201ms
# same-channel; 5000ms is deliberately generous headroom for a loaded CI host
# while staying orders of magnitude below the "never returns" failure this
# group exists to catch.
DPT_TEARDOWN_BUDGET_MS=5000

# Hard bound on how long an outstanding disable is tolerated before it is
# declared wedged and the parked watcher is killed to recover the device.
DPT_TEARDOWN_WEDGE_MS=15000

# A park must hold across this many consecutive 250ms samples before it
# counts as stable. A single snapshot is not enough: a watcher that is
# merely between poll iterations can momentarily look parked, and firing
# the teardown at that instant yields a meaningless "fast" measurement.
DPT_PARK_STABLE_SAMPLES=8

# Wall-clock budget for a watcher to reach a stable park, sampled every
# 250ms. It has to cover draining whatever the ring already held before
# the cursor reaches the tail, plus DPT_PARK_STABLE_SAMPLES of holding
# still. Measured on npu4 the watcher was already parked at the first
# sample and stable 2s later, so this is roughly 4x the observed
# time-to-stable -- enough slack for a chattier ring or a loaded host
# without making a genuine "never parks" failure slow to report.
DPT_PARK_BUDGET_MS=10000

# Wall-clock budget for the post-cleanup "does the device still answer"
# probe. Generous because it only runs on a path that has already failed,
# and an examine on a busy but healthy device is worth waiting out rather
# than misreporting as wedged.
DPT_PROBE_BUDGET_MS=20000

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

# Return "enabled"/"disabled" from xrt-smi examine --firmware-log
# --status, or "unknown" if the call fails. Only the state token goes to
# stdout.
#
# Note this is the driver's view of the enable bit, unlike
# fw_log_confirmed_level() below, which reads the level back out of the
# firmware's own log stream.
fw_log_state_query() {
    local out state
    if ! out=$(xrt_smi --advanced examine -d "${BDF}" --firmware-log --status \
                 2>/dev/null); then
        echo "unknown"
        return 1
    fi
    # pipefail is on and grep exits 1 on no match, so absorb that rather
    # than letting an unparseable status kill the run.
    state=$(grep -oE 'Firmware log status: (enabled|disabled)' <<<"${out}" \
              | awk '{print $NF}' | head -n1) || true
    echo "${state:-unknown}"
}

# Print the driver-reported firmware log level, or "" if not reported.
fw_log_level_query() {
    local out
    if ! out=$(xrt_smi --advanced examine -d "${BDF}" --firmware-log --status \
                 2>/dev/null); then
        echo ""
        return 1
    fi
    grep -oE 'Firmware log level: [0-9]+' <<<"${out}" \
        | awk '{print $NF}' | head -n1 \
        || true
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

# Read the DPT configuration as found and stash it in the ORIG_* globals
# for restore_dpt_state(). Must run before pre_flight() and before any
# test, i.e. while the device still holds whatever the operator left
# there.
#
# Only the features the selected MODE will actually exercise are read, so
# a -log run neither queries nor later touches event-trace, and an
# xrt-smi that lacks the unused subcommand cannot cost the used one its
# restore.
#
# "enabled" is only captured alongside the detail needed to reproduce it
# -- a level for firmware-log, a category list for event-trace. Reported
# as enabled without that detail, the feature is left uncaptured rather
# than replayed from a guess; see the ORIG_* declarations for why that is
# the safe direction.
save_dpt_state() {
    local state level cats

    if [[ "${MODE}" != "trace-only" ]]; then
        state=$(fw_log_state_query) || true
        level=$(fw_log_level_query) || true
        if [[ "${state}" == "disabled" ]] \
           || [[ "${state}" == "enabled" && "${level}" =~ ^[1-9][0-9]*$ ]]; then
            ORIG_LOG_STATE="${state}"
            ORIG_LOG_LEVEL="${level}"
            ORIG_LOG_CAPTURED=1
            info "pre-run firmware-log: ${state} (level ${level:-?})"
        else
            info "pre-run firmware-log state not readable (${state}, level ${level:-?}); leaving it as the tests leave it"
        fi
    fi

    if [[ "${MODE}" != "log-only" ]]; then
        state=$(trace_state_query) || true
        cats=$(trace_state_query_categories) || true
        if [[ "${state}" == "disabled" ]] \
           || [[ "${state}" == "enabled" && -n "${cats}" && "${cats,,}" != "none" ]]; then
            ORIG_TRACE_STATE="${state}"
            ORIG_TRACE_CATS="${cats}"
            ORIG_TRACE_CAPTURED=1
            info "pre-run event-trace: ${state} (categories ${cats:-none})"
        else
            info "pre-run event-trace state not readable (${state}, categories ${cats:-none}); leaving it as the tests leave it"
        fi
    fi
}

# Put each captured DPT feature back the way save_dpt_state() found it.
# Called from teardown() after the watchers are gone, so nothing
# re-enables behind us. A feature that was never captured is not touched.
#
# Categories read back uppercase ("ALL", "CLKPWRGATING") while configure
# spells the everything-keyword lowercase, so "ALL" is special-cased and
# any real category list is replayed verbatim.
restore_dpt_state() {
    if (( ORIG_LOG_CAPTURED )); then
        info "restoring firmware-log: ${ORIG_LOG_STATE} (level ${ORIG_LOG_LEVEL:-?})"
        if [[ "${ORIG_LOG_STATE}" == "enabled" ]]; then
            fw_log_set_level "${ORIG_LOG_LEVEL}" || true
        else
            fw_log_disable
        fi
    fi

    if (( ORIG_TRACE_CAPTURED )); then
        info "restoring event-trace: ${ORIG_TRACE_STATE} (categories ${ORIG_TRACE_CATS:-none})"
        if [[ "${ORIG_TRACE_STATE}" == "enabled" ]]; then
            local cats="${ORIG_TRACE_CATS}"
            if [[ "${cats^^}" == "ALL" ]]; then
                cats="all"
            fi
            xrt_smi --advanced configure -d "${BDF}" --event-trace --enable \
                --categories "${cats}" >/dev/null 2>&1 || true
        else
            trace_force_disable
        fi
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

# EXIT/INT/TERM trap: kill any watchers we spawned, put the DPT features
# this run exercised back the way we found them, remove the temp dir, and
# print the summary. Preserves the triggering exit code.
teardown() {
    local rc=$?
    info "Cleaning up..."

    # Release a deliberately-parked DPT watcher FIRST. If the cross-channel
    # group was interrupted mid-measurement, a teardown may be blocked in
    # synchronize_srcu holding dev_lock, and nothing else below can make
    # progress until that reader drops its SRCU read lock.
    dpt_release_parked_watcher

    local pat
    pat=$(dpt_consumer_pattern)
    pkill -TERM -f "${pat}" 2>/dev/null || true
    sleep 0.3
    pkill -KILL -f "${pat}" 2>/dev/null || true

    # The restore runs after BOTH kills above, and that order is
    # load-bearing twice over. A reader left parked would have its channel
    # woken and re-read behind the replay; and the replay's own configure
    # invocations match the BDF-scoped consumer pattern pkilled just above,
    # so a restore started any earlier would be killed by this very
    # cleanup.
    #
    # Restoring is only meaningful once xrt-smi has been resolved, and only
    # safe while the device still answers. restore_dpt_state() replays the
    # captured configuration with configure ioctls, and those take the same
    # xdna->dev_lock that a teardown blocked in synchronize_srcu is still
    # holding. On a wedged device the replay would therefore block forever
    # -- turning a reported failure into a trap that never returns, with no
    # summary and no exit code, on shared lab hardware.
    #
    # When the cross-channel group could not get a teardown to return, the
    # readers that were pinning it have just been killed above, so whether
    # the device recovered is now a question with a cheap answer. Answer it
    # instead of guessing: on hardware this cleanup did recover the device
    # every time, and a reboot demanded wrongly on a shared lab host gets
    # acted on and destroys somebody else's session.
    if (( DPT_DEVICE_WEDGED )); then
        info "cross-channel group reported an unfinished teardown; checking whether the" \
             "device responds now that the parked readers are gone"
        if dpt_device_responds; then
            info "device RESPONDS after cleanup (xrt-smi examine returned 0):" \
                 "killing the readers recovered it, and no reboot is indicated"
            restore_dpt_state
        else
            info "device did NOT respond to a bounded xrt-smi examine after cleanup:" \
                 "a blocked teardown is most likely still holding dev_lock"
            info "skipping the DPT state restore: its configure ioctls would block on" \
                 "that lock rather than put anything back, and the trap would never return"
            info "the device is left as the tests left it; this host may need a reboot to" \
                 "clear it, and nothing else here can"
        fi
    elif [[ -n "${XRT_SMI_BIN}" && -n "${BDF}" ]]; then
        restore_dpt_state
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

# Compare three watcher captures for total-set equality with a bounded
# convergence retry. A killed `xrt-smi ... --watch` child flushes its final
# poll batch to stdout asynchronously, so `wait` returning does not
# guarantee the redirected file is complete: a single-shot snapshot can
# catch one capture a few entries short and report a spurious mismatch even
# though every watcher receives the identical ring content. Recompute the
# sort -u sets until all three match or a ~5s timeout elapses. A genuine
# divergence never converges, so this preserves the assertion's teeth.
#
# Usage: watchers_converge REGEX SORTED_A SORTED_B SORTED_C OUT_A OUT_B OUT_C
# Writes the final sorted sets to SORTED_* and returns 0 iff equal.
watchers_converge() {
    local re="$1" sA="$2" sB="$3" sC="$4" oA="$5" oB="$6" oC="$7" i
    for (( i = 0; i < 25; i++ )); do
        grep -E "${re}" "${oA}" 2>/dev/null | sort -u >"${sA}" || true
        grep -E "${re}" "${oB}" 2>/dev/null | sort -u >"${sB}" || true
        grep -E "${re}" "${oC}" 2>/dev/null | sort -u >"${sC}" || true
        # Require a non-empty set: three empty captures are equal but must not
        # be reported as a passing "total-set equality" (the per-watcher
        # non-empty checks would already have failed in that case).
        if [ -s "${sA}" ] && cmp -s "${sA}" "${sB}" && cmp -s "${sA}" "${sC}"; then
            return 0
        fi
        sleep 0.2
    done
    return 1
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

    local uniq_A
    if watchers_converge "${FW_LOG_XRTSMI_RE}" \
            "${sorted_A}" "${sorted_B}" "${sorted_C}" \
            "${out_A}" "${out_B}" "${out_C}"; then
        uniq_A=$(wc -l <"${sorted_A}")
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

    local uA
    if watchers_converge "${FW_TRACE_XRTSMI_RE}" \
            "${sorted_A}" "${sorted_B}" "${sorted_C}" \
            "${out_A}" "${out_B}" "${out_C}"; then
        uA=$(wc -l <"${sorted_A}")
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
# Cross-channel teardown (SRCU domain split regression)
#
# fw_log and fw_trace used to share ONE device-wide dpt_srcu domain. A
# watcher parks inside its SRCU read-side critical section --
# amdxdna_dpt_enter() takes srcu_read_lock, then
# amdxdna_dpt_get_data() sleeps in wait_event_interruptible() and only
# amdxdna_dpt_exit() drops the lock, after the wait returns. Teardown
# via amdxdna_dpt_fini_chan() wake_up_all()s only ITS OWN channel's waitqueue
# and then calls synchronize_srcu(). On a shared domain that
# synchronize_srcu also waited for the other channel's parked watcher, which
# nothing in that path wakes, so disabling one channel never returned -- while
# holding xdna->dev_lock, so every later ioctl piled up behind it.
#
# The assertion is a wall-clock one, because that is the only thing that
# distinguishes the two behaviours: with per-channel domains the teardown
# returns in ~200ms, and without them it does not return at all. Being
# fast is necessary but not sufficient, though -- the disable must also
# have exited 0. A command that errors out returns every bit as fast as
# one that did the work, so on timing alone a broken teardown path would
# be recorded as a pass having measured nothing about teardown at all.
#
# Both cases park a fw_trace watcher, because an idle trace ring is the
# most reliable way to keep a watcher parked: with no workload the tail
# stops advancing, so the watcher's cursor reaches the tail and it sleeps
# instead of returning data. A chatty ring is the enemy here -- the
# firmware writing wakes the watcher, it briefly drops the SRCU lock, and
# a teardown can slip through, turning a real deadlock into a spurious
# pass. fw_log is therefore held at level 1 (ERR) for the same reason.
#
# DANGER: on an unfixed driver this wedges the device. The blocked teardown
# sits in uninterruptible D state inside synchronize_srcu() holding
# dev_lock, and the only thing that frees it is killing every reader parked
# in the domain -- not merely the one this group parked, since on a shared
# domain readers left behind by earlier groups hold it open just as
# effectively. Readers do sleep in wait_event_INTERRUPTIBLE, so a signal
# reaches them.
# Everything below is therefore bounded -- no unbounded wait anywhere, not
# even in timeout(1), which would itself block reaping a D-state child.
# The bare wait(1) calls are not an exception: each one only collects the
# exit status of a pid that dpt_wait_pid_ms has already watched exit, so
# there is nothing left for it to wait for. DPT_PARKED_WATCHER_PID is
# tracked globally so the EXIT/INT/TERM trap releases the watcher's whole
# process tree, reader included, even if this script is killed
# mid-measurement.
# ---------------------------------------------------------------------------

# Bounded wait for pid $1 to exit, up to $2 milliseconds, polling at 50ms.
# Returns 0 as soon as the pid is gone, 1 if it is still alive at the
# deadline. Deliberately never waits indefinitely: this is what keeps the
# wedge scenario recoverable.
dpt_wait_pid_ms() {
    local pid="$1" limit="$2" waited=0
    while :; do
        kill -0 "${pid}" 2>/dev/null || return 0
        (( waited >= limit )) && return 1
        sleep 0.05
        waited=$((waited + 50))
    done
}

# Whether /proc/<tid>/stack can be read at all on this kernel (needs
# CONFIG_STACKTRACE, plus root). Without it there is no way to prove a
# watcher really parked, and this group skips rather than assert on timing
# it cannot attribute.
#
# The read has to be attempted, and nothing but the read decides: the mode
# bits on /proc/self/stack say 0400 to its owner, but the open is gated on
# CAP_SYS_ADMIN and is refused outright under kernel lockdown, so [[ -r ]]
# answers yes where the read fails and the group would report "never
# parked" on a kernel that simply cannot answer the question. It also
# answers no where the read would succeed, because it tests the real uid
# while the open uses the effective one, and the group would skip a check
# the host could have run.
dpt_stack_probe_available() {
    cat /proc/self/stack >/dev/null 2>&1
}

# Echo the live pids of the watcher process tree rooted at $1, parents
# before children, or nothing if the root is already gone.
#
# The pid a watcher is launched under is NOT necessarily the process that
# blocks in the kernel. A stock install ships /opt/xilinx/xrt/bin/xrt-smi
# as a POSIX shell wrapper that forks bin/unwrapped/xrt-smi and then sits
# in wait4(), so $! names a /bin/sh: its state is S, but its stack is
# do_wait and can never hold a DPT frame, and a signal delivered to it
# does not reach the reader. Other installs -- and possibly future ones --
# exec the binary directly, with no wrapper layer at all.
#
# Walking the subtree covers both without assuming either shape: with no
# children the root is the only pid returned, which is exactly the
# no-wrapper case. Callers re-walk on every sample rather than resolving
# once, so a wrapper that has not forked yet at launch is simply picked up
# by the next sample instead of being latched onto by a fixed sleep.
dpt_watcher_tree() {
    local pid="$1" kid
    [[ -z "${pid}" ]] && return 0
    kill -0 "${pid}" 2>/dev/null || return 0
    printf '%s\n' "${pid}"
    while read -r kid; do
        [[ -n "${kid}" ]] || continue
        dpt_watcher_tree "${kid}"
    done < <(pgrep -P "${pid}" 2>/dev/null || true)
    return 0
}

# Regex matching a kernel stack frame that means "parked in the amdxdna
# DPT watch path". Matched as a SET rather than as amdxdna_dpt_get_data
# exactly, because that function is static and the compiler is free to
# inline it into amdxdna_get_fw_log / amdxdna_get_fw_trace, in which case
# the sleeping frame carries the caller's name instead. It was observed
# un-inlined on the npu4 build this group was validated against, but that
# is one kernel built by one compiler and the set costs nothing.
#
# Shared by the park proof (dpt_parked_stack) and the recovery lever
# (dpt_release_dpt_parked_readers) on purpose: the lever must recognise
# exactly the state the proof calls "parked", or it would fail to release
# readers the proof would have accepted.
DPT_PARK_FRAME_RE='amdxdna_(dpt_get_data|get_fw_log|get_fw_trace)'

# Echo "pid=<pid> tid=<tid> state=<S>" plus the kernel stack of the first
# thread anywhere in the watcher tree rooted at $1 that is parked in the
# DPT watch path, or nothing if no thread is.
#
# A park is two independent facts, and both are required: the thread is in
# interruptible sleep (state S in /proc/<tid>/stat) and its kernel stack is
# inside the amdxdna DPT get-data ioctl. State alone is far too weak --
# xrt-smi sleeps in plenty of other places, and the shell wrapper that
# dpt_watcher_tree exists to see past sits in wait4() in state S for its
# whole life -- while the stack alone does not prove the thread is asleep
# rather than passing through.
dpt_parked_stack() {
    local root="$1" pid tdir tid stat_line state stack
    [[ -z "${root}" ]] && return 0
    while read -r pid; do
        for tdir in /proc/"${pid}"/task/*; do
            [[ -r "${tdir}/stack" ]] || continue
            stat_line=$(cat "${tdir}/stat" 2>/dev/null) || continue
            # "pid (comm) state ...", and comm may itself contain spaces
            # and parentheses, so split after the LAST ") ".
            state="${stat_line##*') '}"
            state="${state%% *}"
            [[ "${state}" == "S" ]] || continue
            stack=$(cat "${tdir}/stack" 2>/dev/null) || continue
            grep -qE "${DPT_PARK_FRAME_RE}" <<<"${stack}" || continue
            tid=$(basename "${tdir}")
            printf 'pid=%s tid=%s state=%s\n%s' \
                "${pid}" "${tid}" "${state}" "${stack}"
            return 0
        done
    done < <(dpt_watcher_tree "${root}")
    return 0
}

# Launch an --event-trace --watch consumer and wait for it to park stably
# inside the driver's wait_event_interruptible. Sets
# DPT_PARKED_WATCHER_PID as soon as the process exists, so the trap can
# release it even if parking never completes, and writes the proving
# evidence to the file $3.
#
# MUST be called directly, never through $( ): the watcher has to be a
# child of the calling shell so that DPT_PARKED_WATCHER_PID is visible to
# the trap and so dpt_release_parked_watcher can wait on it. That is why
# the evidence goes to a file instead of stdout.
#
# Returns: 0 parked stably, 1 never parked, 2 exited before parking,
#          3 no stack evidence available on this kernel.
dpt_park_trace_watcher() {
    local out="$1" err="$2" evidence="$3"
    local pid stack samples stable=0 i

    : >"${out}"; : >"${err}"; : >"${evidence}"
    xrt_smi --advanced examine -d "${BDF}" --event-trace --watch \
        >"${out}" 2>"${err}" &
    pid=$!
    DPT_PARKED_WATCHER_PID="${pid}"

    dpt_stack_probe_available || return 3

    # The park is looked for anywhere in the watcher's process tree, not
    # just in ${pid}, because ${pid} may be a shell wrapper -- see
    # dpt_watcher_tree. ${pid} is still the right liveness check: it is the
    # process this shell spawned, so its exit means the watcher run is
    # over however many layers it had.
    samples=$(( DPT_PARK_BUDGET_MS / 250 ))
    for (( i = 0; i < samples; i++ )); do
        kill -0 "${pid}" 2>/dev/null || return 2
        stack=$(dpt_parked_stack "${pid}")
        if [[ -n "${stack}" ]]; then
            stable=$((stable + 1))
            if (( stable >= DPT_PARK_STABLE_SAMPLES )); then
                printf '%s' "${stack}" >"${evidence}"
                return 0
            fi
        else
            # Woke up: the ring is still advancing. Restart the streak so
            # only a genuinely quiet, continuously parked watcher counts.
            stable=0
        fi
        sleep 0.25
    done
    return 1
}

# Release the deliberately-parked watcher. This is the recovery lever for
# the wedge scenario: a blocked amdxdna_dpt_fini_chan() cannot make
# progress until this reader drops its SRCU read lock. Idempotent, safe to
# call from the trap, and safe to call when nothing was ever parked.
#
# It signals the whole watcher tree, not just the pid the watcher was
# launched under, and that is the safety-critical part rather than a
# tidiness one: measured on npu4, a SIGTERM delivered to the shell wrapper
# alone left the reader parked in wait_event_interruptible, so on an
# unfixed driver this "recovery" would have stranded the board instead of
# freeing it.
#
# The tree is snapshotted BEFORE the first signal. Killing the wrapper
# reparents the reader to init, after which pgrep -P cannot find it and
# the reader we most need to reach becomes invisible.
dpt_release_parked_watcher() {
    local root="${DPT_PARKED_WATCHER_PID}"
    local pids=()
    local pid i

    [[ -z "${root}" ]] && return 0
    DPT_PARKED_WATCHER_PID=""

    while read -r pid; do
        [[ -n "${pid}" ]] && pids+=("${pid}")
    done < <(dpt_watcher_tree "${root}")

    # Deepest first: the reader is what holds the SRCU read lock, and
    # reaching it before the shell that reaps it keeps the wrapper around
    # to be waited on rather than leaving an orphan behind.
    for (( i = ${#pids[@]} - 1; i >= 0; i-- )); do
        kill -TERM "${pids[i]}" 2>/dev/null || true
    done
    for (( i = ${#pids[@]} - 1; i >= 0; i-- )); do
        if ! dpt_wait_pid_ms "${pids[i]}" 3000; then
            kill -KILL "${pids[i]}" 2>/dev/null || true
            dpt_wait_pid_ms "${pids[i]}" 3000 || true
        fi
    done
    wait "${root}" 2>/dev/null || true
}

# Hard bound on how many ancestors dpt_proc_depth will walk. The walk is
# for ORDERING only -- no ancestor is ever signalled -- but it still needs
# a bound: an earlier version of this lever walked the parent chain until
# it reached pid 1 and killed this script's own harness shell on the way.
# Nothing legitimate in an xrt-smi launch is more than a handful of levels
# deep, so a walk that exceeds this is a bug or a pid-reuse race, and the
# right answer is to stop rather than to keep climbing.
DPT_PROC_DEPTH_MAX=16

# Echo how many ancestors pid $1 has, stopping at DPT_PROC_DEPTH_MAX, at
# pid 1, or at the first unreadable /proc entry. Used only to sort kill
# candidates deepest-first; the ancestors themselves are never touched.
dpt_proc_depth() {
    local pid="$1" depth=0 stat_line rest ppid
    while (( depth < DPT_PROC_DEPTH_MAX )); do
        [[ -n "${pid}" && "${pid}" != "0" && "${pid}" != "1" ]] || break
        stat_line=$(cat "/proc/${pid}/stat" 2>/dev/null) || break
        # "pid (comm) state ppid ...", and comm may contain spaces and
        # parentheses, so split after the LAST ") ".
        rest="${stat_line##*') '}"
        read -r _ ppid _ <<<"${rest}"
        [[ -n "${ppid}" ]] || break
        pid="${ppid}"
        depth=$((depth + 1))
    done
    printf '%s' "${depth}"
}

# Echo the tid of the first thread of pid $1 that is parked in the DPT
# watch path (interruptible sleep plus a DPT_PARK_FRAME_RE frame), or
# nothing. Same two-fact test as dpt_parked_stack, applied to one process
# rather than to a process tree.
dpt_parked_tid() {
    local pid="$1" tdir stat_line state
    [[ -n "${pid}" ]] || return 0
    for tdir in /proc/"${pid}"/task/*; do
        [[ -r "${tdir}/stack" ]] || continue
        stat_line=$(cat "${tdir}/stat" 2>/dev/null) || continue
        state="${stat_line##*') '}"
        state="${state%% *}"
        [[ "${state}" == "S" ]] || continue
        grep -qE "${DPT_PARK_FRAME_RE}" "${tdir}/stack" 2>/dev/null || continue
        basename "${tdir}"
        return 0
    done
    return 0
}

# Release EVERY reader parked in this device's DPT watch path, not just the
# one this group tracked, and echo how many were signalled.
#
# dpt_release_parked_watcher alone is not a recovery lever for a full-script
# run. By the time this group runs, the earlier groups have left on the
# order of twenty other --watch consumers parked in the DPT wait path, and
# on a driver with the shared SRCU domain every one of them keeps that
# domain occupied. Killing only the pid this group happens to have
# bookkeeping for leaves the teardown blocked on all the others, so the
# group would report a wedged device it could in fact have recovered.
#
# Readers are identified by their KERNEL STACK rather than by pid
# bookkeeping. That is what makes this work at all here: these readers were
# launched by earlier groups that kept no record of them, and stack identity
# also survives the reparenting that defeats pgrep -P walking.
#
# SCOPE -- this runs on shared lab hosts, so a process is signalled only if
# BOTH hold:
#
#   1. its command line matches dpt_consumer_pattern, i.e. it is an xrt-smi
#      --firmware-log/--event-trace consumer aimed at THIS BDF. This is the
#      same bar teardown()'s pkill already uses, and the candidate set comes
#      from pgrep against that pattern rather than from a sweep of all of
#      /proc, so a process that does not match is never even examined.
#   2. it has a thread parked in DPT_PARK_FRAME_RE, the same frame set the
#      park proof uses.
#
# The intersection is strictly narrower than the existing pkill: every
# process this can kill, teardown()'s pkill would already have killed.
# Notably the disable under measurement cannot be caught by it even though
# its command line does match (1): it is blocked in synchronize_srcu, which
# is an uninterruptible D-state wait under amdxdna_dpt_fini_chan, so it
# fails both the state and the frame half of (2). It is excluded by pid as
# well, so that guarantee does not rest on reading stacks correctly.
dpt_release_dpt_parked_readers() {
    local pat cand tid depth
    local -a ordered=()
    local entry pid i signalled=0

    pat=$(dpt_consumer_pattern)

    while read -r cand; do
        [[ -n "${cand}" ]] || continue
        # Never signal this script, the shell it runs in, or the very
        # disable whose duration is being measured.
        [[ "${cand}" == "$$" || "${cand}" == "${BASHPID}" ]] && continue
        [[ -n "${DPT_DISABLE_PID}" && "${cand}" == "${DPT_DISABLE_PID}" ]] && continue
        tid=$(dpt_parked_tid "${cand}")
        [[ -n "${tid}" ]] || continue
        depth=$(dpt_proc_depth "${cand}")
        ordered+=("${depth} ${cand}")
    done < <(pgrep -f "${pat}" 2>/dev/null || true)

    (( ${#ordered[@]} == 0 )) && { printf '0'; return 0; }

    # Deepest first, for the same reason dpt_release_parked_watcher does
    # it: reach the reader that holds the SRCU read lock before any shell
    # that would reap it.
    local -a pids=()
    while read -r entry; do
        [[ -n "${entry}" ]] && pids+=("${entry#* }")
    done < <(printf '%s\n' "${ordered[@]}" | sort -k1,1nr -k2,2n)

    for pid in "${pids[@]}"; do
        kill -TERM "${pid}" 2>/dev/null && signalled=$((signalled + 1))
    done
    for (( i = 0; i < ${#pids[@]}; i++ )); do
        if ! dpt_wait_pid_ms "${pids[i]}" 3000; then
            kill -KILL "${pids[i]}" 2>/dev/null || true
            dpt_wait_pid_ms "${pids[i]}" 3000 || true
        fi
    done

    printf '%s' "${signalled}"
}

# Quiesce the --watch consumers earlier groups left parked on this device,
# using the same BDF-scoped pattern teardown() and pre_flight() use, and
# wait a bounded time for them to go.
#
# This is a precondition for the cross-channel group rather than part of its
# measurement: see the comment in test_fw_dpt_cross_channel_teardown for why
# leftover readers have to be gone before the control runs.
dpt_quiesce_leftover_readers() {
    local pat pid
    local -a leftover=()

    pat=$(dpt_consumer_pattern)
    while read -r pid; do
        [[ -n "${pid}" ]] && leftover+=("${pid}")
    done < <(pgrep -f "${pat}" 2>/dev/null || true)

    (( ${#leftover[@]} == 0 )) && return 0

    info "quiescing ${#leftover[@]} leftover DPT consumer(s) from earlier groups (BDF-scoped)"
    pkill -TERM -f "${pat}" 2>/dev/null || true
    for pid in "${leftover[@]}"; do
        dpt_wait_pid_ms "${pid}" 3000 || true
    done
    pkill -KILL -f "${pat}" 2>/dev/null || true
    for pid in "${leftover[@]}"; do
        dpt_wait_pid_ms "${pid}" 3000 || true
    done
}

# Bounded probe of whether the device still answers an ordinary xrt-smi
# query. Used after cleanup to report what actually happened to the device
# instead of guessing, and to decide whether restoring the captured DPT
# state can be attempted at all. Returns 0 only if the device answered.
#
# Deliberately NOT timeout(1). The state this probe exists to detect is a
# teardown still holding xdna->dev_lock, and everything behind that lock
# blocks in mutex_lock(), which is TASK_UNINTERRUPTIBLE --
# amdxdna_drm_get_info_ioctl() takes dev_lock unconditionally, so the
# examine below is exactly such a caller. A child in D state is reaped by
# no signal, and timeout(1) waits for the child it signalled, so it would
# hang precisely in the case this probe has to answer. The measurement
# path avoids timeout(1) for the same reason.
#
# So the examine runs as a background job watched by the same bounded
# poll. A probe still running at the deadline is reported as "did not
# respond": the process is left behind, because nothing can reap it until
# the lock is released, but this function returns and the trap goes on to
# print a summary and exit.
#
# The xrt_smi() wrapper is not used here: backgrounding a shell function
# makes $! the pid of a subshell rather than of the examine itself.
dpt_device_responds() {
    local pid rc=0

    [[ -n "${XRT_SMI_BIN}" && -n "${BDF}" ]] || return 1

    LD_LIBRARY_PATH="$(xrt_smi_ld_path)" \
        "${XRT_SMI_BIN}" examine -d "${BDF}" >/dev/null 2>&1 &
    pid=$!

    if ! dpt_wait_pid_ms "${pid}" "${DPT_PROBE_BUDGET_MS}"; then
        # Best effort only: a task blocked on dev_lock will not take it.
        kill -TERM "${pid}" 2>/dev/null || true
        return 1
    fi

    # Collects the status of a pid already observed to have exited, so
    # this cannot block.
    wait "${pid}" || rc=$?
    return "${rc}"
}

# Run "configure --<$1> --disable" in the background, recording its own
# wall-clock duration in milliseconds into the file $2. Sets
# DPT_DISABLE_PID to the background pid.
#
# The background job exits with the disable's own exit status, so the
# caller can require the command to have SUCCEEDED and not merely to have
# returned. Timing alone cannot tell a disable that failed fast from one
# that succeeded fast, and only the latter says anything about teardown.
# The duration is still stamped on the failing path, so a failure can be
# reported with the measurement that produced it.
#
# Backgrounded on purpose rather than wrapped in timeout(1): on an unfixed
# driver this command never returns until the parked watcher dies, and
# timeout would be no help because it waits for a child that is stuck in
# uninterruptible D state inside synchronize_srcu(). The caller polls with
# dpt_wait_pid_ms and kills the watcher to recover.
#
# Like dpt_park_trace_watcher, this must be called directly rather than
# through $( ), so the job stays a child of the calling shell and
# DPT_DISABLE_PID survives for both the poll and the later wait.
dpt_disable_timed_bg() {
    local opt="$1" stamp="$2"
    : >"${stamp}"
    (
        drc=0
        t0=$(date +%s%N)
        LD_LIBRARY_PATH="$(xrt_smi_ld_path)" \
            "${XRT_SMI_BIN}" --advanced configure -d "${BDF}" \
                "--${opt}" --disable >/dev/null 2>&1 || drc=$?
        printf '%s' "$(( ($(date +%s%N) - t0) / 1000000 ))" >"${stamp}"
        exit "${drc}"
    ) &
    DPT_DISABLE_PID=$!
}

# Park a trace watcher, then time a disable of the channel named by the
# xrt-smi option $2 while that watcher is parked.
#
#   $1 case_label : label for the assertion text
#   $2 opt        : "firmware-log" (cross-channel) or "event-trace"
#                   (same-channel)
dpt_measure_teardown() {
    local case_label="$1" opt="$2"
    local out="${TMPDIR_}/dpt_park_${opt}.out"
    local err="${TMPDIR_}/dpt_park_${opt}.err"
    local evidence="${TMPDIR_}/dpt_park_${opt}.stack"
    local stamp="${TMPDIR_}/dpt_disable_${opt}.ms"
    local rc dpid drc elapsed released

    # Two jobs at once. Level 1 (ERR) is the quietest level the driver
    # accepts, which keeps the firmware from writing while the watcher is
    # trying to stay parked. Enabling also guarantees fw_log is ACTIVE, so
    # that the cross-channel case really does tear a live handle down: on an
    # already-disabled channel amdxdna_dpt_fini_chan() returns immediately
    # without ever reaching synchronize_srcu, and the measurement would be
    # fast for entirely the wrong reason.
    if ! fw_log_set_level 1; then
        fail "[${case_label}] configure --firmware-log --enable --log-level 1 failed"
        return
    fi

    trace_force_disable
    if ! xrt_smi --advanced configure -d "${BDF}" --event-trace --enable \
            --categories all >/dev/null 2>&1; then
        fail "[${case_label}] configure --event-trace --enable failed; cannot park a watcher"
        return
    fi

    # Called directly, not through $( ), so DPT_PARKED_WATCHER_PID lands in
    # this shell and the trap can always release the watcher.
    rc=0
    dpt_park_trace_watcher "${out}" "${err}" "${evidence}" || rc=$?
    case "${rc}" in
    0)  ;;
    2)  dpt_release_parked_watcher
        fail "[${case_label}] trace watcher exited before parking." \
             "stderr: $(head -c 256 "${err}")"
        return ;;
    3)  dpt_release_parked_watcher
        skip "[${case_label}] /proc/<tid>/stack unreadable (kernel without" \
             "CONFIG_STACKTRACE?); the park cannot be proven, so the timing" \
             "assertion below would be vacuous"
        return ;;
    *)  dpt_release_parked_watcher
        fail "[${case_label}] trace watcher never parked in the DPT watch path;" \
             "a teardown measured now would complete quickly for the wrong reason"
        return ;;
    esac

    pass "[${case_label}] trace watcher parked in the DPT watch path (SRCU read lock held)"
    emit_snippet "[${case_label}] parked watcher evidence:" "$(cat "${evidence}")" 4

    dpt_disable_timed_bg "${opt}" "${stamp}"
    dpid="${DPT_DISABLE_PID}"
    info "[${case_label}] disabling --${opt} (pid=${dpid}) with the trace watcher parked"

    if ! dpt_wait_pid_ms "${dpid}" "${DPT_TEARDOWN_WEDGE_MS}"; then
        # The unfixed-driver signature: the teardown is blocked in
        # synchronize_srcu holding dev_lock, and only a parked reader
        # dropping its SRCU read lock can let it finish.
        info "[${case_label}] disable still outstanding after ${DPT_TEARDOWN_WEDGE_MS}ms;" \
             "releasing the parked watcher to try to unwedge the device"
        dpt_release_parked_watcher
        if dpt_wait_pid_ms "${dpid}" 10000; then
            fail "[${case_label}] disable of --${opt} blocked for more than" \
                 "${DPT_TEARDOWN_WEDGE_MS}ms and completed only once the parked watcher" \
                 "was killed: the teardown waited on a reader it never woke"
            return
        fi

        # The watcher this group tracked is not necessarily the only reader
        # holding the domain: on a shared SRCU domain every reader parked by
        # an earlier group counts too, and this group kept no pids for those.
        info "[${case_label}] still outstanding after releasing this group's watcher;" \
             "releasing every reader parked in this device's DPT watch path"
        released=$(dpt_release_dpt_parked_readers)
        info "[${case_label}] released ${released} parked DPT reader(s)"
        if dpt_wait_pid_ms "${dpid}" 10000; then
            fail "[${case_label}] disable of --${opt} blocked for more than" \
                 "${DPT_TEARDOWN_WEDGE_MS}ms and completed only after releasing" \
                 "${released} reader(s) parked in the DPT watch path: the teardown" \
                 "waited on readers it never woke"
            return
        fi

        # Say only what is known here. The teardown did not return inside
        # the budget, so it may still hold dev_lock -- but cleanup has not
        # run yet, and on hardware the ordinary teardown() has recovered
        # this every time, so a verdict on the host belongs after cleanup
        # and not in this message.
        DPT_DEVICE_WEDGED=1
        fail "[${case_label}] disable of --${opt} did not complete within" \
             "${DPT_TEARDOWN_WEDGE_MS}ms, nor after releasing this group's watcher and" \
             "${released} other reader(s) parked in the DPT watch path. The teardown may" \
             "still hold dev_lock, in which case amdxdna ioctls will block. Cleanup will" \
             "now try to recover the device and will report whether it responds" \
             "afterwards -- read that result before concluding anything about this host"
        return
    fi

    dpt_release_parked_watcher

    elapsed=$(cat "${stamp}" 2>/dev/null || true)
    if [[ -z "${elapsed}" ]]; then
        fail "[${case_label}] disable of --${opt} returned but recorded no duration"
        return
    fi

    # The job is already gone, so this only collects its status; it never
    # blocks, and the wedge path above returns before reaching here. The
    # status has to be checked before the timing is trusted: a disable
    # that errored out in a few milliseconds is fast for a reason that
    # says nothing at all about teardown, and on time alone it is
    # indistinguishable from one that really did tear a live handle down.
    drc=0
    wait "${dpid}" || drc=$?
    if (( drc != 0 )); then
        fail "[${case_label}] disable of --${opt} FAILED with exit status ${drc}" \
             "after ${elapsed}ms. The command errored out instead of tearing the" \
             "channel down, so this run measured nothing about teardown -- note that" \
             "this is NOT the deadlock signature, which is a disable that never" \
             "returns at all"
        return
    fi

    if (( elapsed <= DPT_TEARDOWN_BUDGET_MS )); then
        pass "[${case_label}] disable of --${opt} succeeded in ${elapsed}ms" \
             "(<=${DPT_TEARDOWN_BUDGET_MS}ms)"
    else
        fail "[${case_label}] disable of --${opt} took ${elapsed}ms," \
             "over the ${DPT_TEARDOWN_BUDGET_MS}ms budget"
    fi
}

test_fw_dpt_cross_channel_teardown() {
    group "fw_dpt: cross-channel teardown with a watcher parked"

    # Quiesce the readers earlier groups left parked BEFORE measuring
    # anything. This is a precondition, not tidiness: the earlier watch
    # groups leave on the order of twenty --watch consumers parked in the
    # DPT wait path, and on a driver with the shared SRCU domain every one
    # of them holds that domain open. Measured on hardware that is what
    # made the same-channel case below -- which cannot deadlock on its own --
    # block and wedge the device, and because a failure is fatal the
    # cross-channel assertion this group exists for never ran at all.
    #
    # It cannot mask the wedge the group looks for, because the group
    # recreates that condition itself immediately afterwards with a watcher
    # of its own. What is removed is unrelated leftover readers, never the
    # parked reader whose presence is the entire point. It does not weaken
    # the anti-vacuous-pass guarantees either: those rest on proving this
    # group's own park (a stable stack matching DPT_PARK_FRAME_RE) and on
    # requiring the disable to have exited 0, and neither involves any
    # other process.
    dpt_quiesce_leftover_readers

    # The same-channel control runs FIRST, deliberately. It drives the exact
    # same park-then-measure machinery over the path that cannot deadlock
    # by construction -- fini_chan wakes the very waitqueue its watcher
    # sleeps on -- so it proves the harness can park a watcher and time a
    # teardown at all. Without it a fast cross-channel result is
    # indistinguishable from a reproducer that quietly never parked
    # anything.
    #
    # Structurally sound is not the same as safe to run, though. With
    # readers left parked in a shared domain by earlier groups, this
    # same-channel case is the one that blocked and wedged the device on
    # hardware; it is only the harmless case once the quiesce above has
    # happened.
    dpt_measure_teardown "same-channel control" "event-trace"

    # THE DIRECTION IS DELIBERATE: park a TRACE watcher, tear down the LOG.
    # Do not "simplify" this by swapping the channels. The reverse direction
    # is not a detector at all: on an unfixed driver, park-trace then
    # disable-log wedges reproducibly (~515ms to wedge), while park-log
    # then disable-trace returned in ~503ms with status 0 on every attempt
    # and never wedged.
    #
    # That asymmetry is understood, not luck. Tearing down event-trace
    # makes the firmware log its own shutdown -- a parked watcher captured
    # exactly these entries:
    #
    #     [0] I: Got stop event trace command
    #     [H] I: Stopping event trace
    #     [H] I: Event trace stopped successfully
    #
    # Those writes advance the log tail, which wakes the parked log reader,
    # which drops its SRCU read lock, which lets the very teardown it was
    # meant to block run to completion. Flipping the channels would turn this
    # group into one that passes on the buggy driver it exists to catch.
    dpt_measure_teardown "cross-channel" "firmware-log"

    # Leave the device the way the other groups expect to find it.
    trace_force_disable
    fw_log_set_level 3 || true
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

    # Capture before arming the trap that replays it, and before
    # pre_flight() touches anything.
    save_dpt_state

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

    # Needs fw_log and fw_trace active at the same time to tear one down
    # while a watcher is parked on the other, so it has no meaning in the
    # single-channel modes.
    if [[ "${MODE}" == "both" ]]; then
        test_fw_dpt_cross_channel_teardown
    fi
}

main "$@"
