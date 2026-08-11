# amdxdna perf tracing tools

Two scripts for capturing and analyzing latency of amdxdna driver operations
using `perf`/ftrace. They work together as a pipeline:

```
npu_perf_trace.sh  --(capture)-->  perf.converted.out  --(analyze)-->  npu_perf_analyze.sh
```

Both scripts support `-h`/`--help` and print full usage without requiring
root:

```bash
./npu_perf_trace.sh --help
./npu_perf_analyze.sh --help
```

These tools are backend-agnostic: the amdxdna driver's tracepoints all live
under a single `TRACE_SYSTEM amdxdna` (see
`include/trace/events/amdxdna.h`), shared by the aie2, aie4, and ve2
backends alike. Everything below applies equally to all three; the VE2
examples are called out because VE2 has some tracepoints (and usage
patterns, e.g. multiple hwctx sharing a partition) the PCI backends don't.

## 1. `npu_perf_trace.sh` — capture a trace

```bash
sudo ./npu_perf_trace.sh [-libdir <path-to-xrt-libs>] <command to run> [args...]
```

What it does:
1. Finds the loaded amdxdna accel device under `/sys/kernel/debug/accel`.
2. Adds XRT's `sdt_xrt:*` USDT probes (from `libxrt_coreutil.so` /
   `libxrt_driver_xdna.so`, via `perf buildid-cache` + `perf probe`).
3. Runs `perf record -e amdxdna:* -e sdt_xrt:* -a <command>` — i.e. captures
   every `amdxdna:*` tracepoint (hwctx init/fini, partition init, IRQ,
   command submit/wait/complete, scheduler work, mailbox, ...) plus XRT's
   USDT probes, system-wide, while `<command>` runs.
4. Converts the result with `perf script --reltime --ns` and substitutes
   raw IOCTL numbers with their human-readable names (using
   `/sys/kernel/debug/accel/<dev>/ioctl_id`).
5. Writes the final text trace to `perf.converted.out` in the current
   directory (used as the default input for `npu_perf_analyze.sh`).

Must be run as **root** (needed for `perf record`/`perf probe` and to read
`/sys/kernel/debug/accel` and `/sys/kernel/debug/tracing`).

Example:

```bash
cd test_files
sudo /path/to/npu_perf_trace.sh ./host.exe
```

## 2. `npu_perf_analyze.sh` — measure latency between two events

```bash
./npu_perf_analyze.sh [-file <perf.converted.out>] [-range <start:end>] [-key <pattern>] \
    <event1_pattern> <event2_pattern>
```

Scans `perf.converted.out` (or `-f`/`-file <path>`) for every line matching
`event1_pattern`, and every line matching `event2_pattern` (plain `egrep`
patterns matched anywhere in the line), then pairs each `event2` occurrence
with the closest preceding, not-yet-used `event1` occurrence and reports the
average/largest/smallest time delta (in nanoseconds) across all pairs.

Options:
- `-file`/`-f <path>`: input file (default `perf.converted.out`)
- `-range`/`-r <start:end>`: only consider the `[start, end)` slice of the
  matched pairs (0-indexed, in the order they were found)
- `-key`/`-k <pattern>`: only consider lines that *also* match this pattern
  before pairing. Use this to correlate paired events by an identifying
  field (e.g. `hwctx=3` or `seq=42`) instead of relying purely on nearest
  timestamp, which can mis-pair events when multiple contexts are
  interleaved (e.g. VE2, where several hwctx can share a partition).

### Examples

Time from an XRT wait-cmd ioctl call to its return (generic, all backends):

```bash
./npu_perf_analyze.sh \
  "sdt_xrt:ioctl_entry: \(.+\) arg1=DRM_IOCTL_AMDXDNA_WAIT_CMD" \
  "sdt_xrt:ioctl_exit: \(.+\) arg1=DRM_IOCTL_AMDXDNA_WAIT_CMD"
```

VE2 partition-init latency for a specific hwctx:

```bash
./npu_perf_analyze.sh -k "hwctx=3" \
  "amdxdna:xdna_partition_init_start" "amdxdna:xdna_partition_init_done"
```

VE2 command submit -> complete latency for a specific sequence number:

```bash
./npu_perf_analyze.sh -k "seq=42" \
  "amdxdna:xdna_cmd_submit" "amdxdna:xdna_cmd_complete"
```

VE2 hwctx init latency (no `name` field available yet at this point in the
driver, so pair on `hwctx_id` alone — see comment in
`include/trace/events/amdxdna.h`):

```bash
./npu_perf_analyze.sh -k "hwctx=3" \
  "amdxdna:xdna_hwctx_init_start" "amdxdna:xdna_hwctx_init_done"
```

Only look at pairs 10 through 50 (0-indexed) from a large capture:

```bash
./npu_perf_analyze.sh -r 10:50 \
  "amdxdna:xdna_cmd_wait_start" "amdxdna:xdna_cmd_wait_done"
```

## VE2 tracepoint reference

All of the following are under the single `amdxdna:*` group (see
`include/trace/events/amdxdna.h` for exact field names/types):

| Stage | Start event | Done/complete event | Key fields |
|---|---|---|---|
| hwctx create/destroy | `xdna_hwctx_init_start` / `xdna_hwctx_fini_start` | `xdna_hwctx_init_done` / `xdna_hwctx_fini_done` | `hwctx` |
| Partition init | `xdna_partition_init_start` | `xdna_partition_init_done` | `hwctx`, `start_col`, `num_col` |
| Scheduler work | `xdna_sched_work_start` | `xdna_sched_work_done` | `hwctx`, `start_col` |
| Mgmt schedule cmd | `xdna_mgmt_schedule_cmd_start` | `xdna_mgmt_schedule_cmd_done` | `hwctx` |
| Command submit | `xdna_cmd_submit_start` | `xdna_cmd_submit` | `hwctx`, `seq`, `op` |
| Command wait | `xdna_cmd_wait_start` | `xdna_cmd_wait_done` | `hwctx`, `seq` |
| Command complete | — | `xdna_cmd_complete` | `hwctx`, `seq`, `state` |
| Queue indices | `xdna_queue_write_index` | `xdna_queue_read_index` | `hwctx`, `seq` |
| IRQ handling | `xdna_irq_enter` | `xdna_irq_exit` | `partition`, `hwctx` |

For a higher-level, ready-made report covering all of the stages above with
one command, see `test/*/xrt_profiling` (`xrt_profile --start` / `--stop`)
instead — it enables/parses these same tracepoints automatically and
produces a per-command latency breakdown without manually pairing events.

## Troubleshooting

- `No events found for ...`: usually means `perf.converted.out` has no
  matching lines. Confirm the tracepoint group name matches what's actually
  registered on your board: `perf list | grep amdxdna` or
  `ls /sys/kernel/debug/tracing/events/amdxdna/`.
- `<file> is not found`: run `npu_perf_trace.sh` first, or pass `-file` to
  point at an existing trace.
- Getting mis-paired/nonsensical diffs on VE2: add `-key "hwctx=<id>"` or
  `-key "seq=<n>"` to disambiguate when multiple hw contexts are active
  concurrently.
