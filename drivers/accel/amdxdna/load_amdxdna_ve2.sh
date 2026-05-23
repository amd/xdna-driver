#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Load VE2 amdxdna and xilinx-aie (insmod does not resolve depends).
#
# Usage:
#   ./load_amdxdna_ve2.sh [path/to/modules]
# Default: same directory as this script (copy xilinx-aie.ko, amdxdna.ko here).

set -e

MODDIR="${1:-$(cd "$(dirname "$0")" && pwd)}"

load_one() {
	local name="$1"
	local ko="$MODDIR/$name.ko"
	if [ ! -f "$ko" ]; then
		echo "Missing $ko" >&2
		return 1
	fi
	if lsmod | awk '{print $1}' | grep -qx "${name/-/_}" 2>/dev/null || \
	   lsmod | awk '{print $1}' | grep -qx "$name" 2>/dev/null; then
		echo "$name already loaded"
		return 0
	fi
	echo "insmod $ko"
	insmod "$ko"
}

load_one xilinx-aie
load_one amdxdna

echo "OK: amdxdna stack loaded"
lsmod | grep -E 'gpu_sched|xilinx|amdxdna' || true
