#! /bin/bash --

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
#
# Run checkpatch.pl against the driver tree using the latest version
# pulled fresh from the mainline Linux kernel (torvalds/linux.git) on
# every invocation, rather than whatever ships with the kernel
# installed on the build host. An older locally-installed kernel can
# hide warnings and errors that newer checkpatch versions would flag,
# so we never cache: each run downloads the current mainline script.
#
# On every run we print the blob SHA of the downloaded file and the
# most recent mainline commit that touched scripts/checkpatch.pl, so
# it is always clear exactly which version was used.

set -u

target_dir=$1

KERNEL_RAW_BASE="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/scripts"
KERNEL_LOG_BASE="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/scripts"

WORKDIR=$(mktemp -d -t xdna-checkpatch.XXXXXX)
trap 'rm -rf "${WORKDIR}"' EXIT
CHECKPATCH="${WORKDIR}/checkpatch.pl"

# Read header value from a curl headers file (CR-stripped, case-insensitive).
# Usage: header_value HEADERS_FILE NAME
header_value() {
    local file=$1 name=$2
    tr -d '\r' < "${file}" \
        | sed -n "s/^[[:space:]]*${name}:[[:space:]]*//Ip" \
        | head -n1
}

# download URL DEST
# Downloads URL to DEST and echoes the response ETag (blob SHA) on stdout.
# Returns non-zero on failure.
download() {
    local url=$1 dest=$2 headers
    headers=$(mktemp -p "${WORKDIR}") || return 1
    if ! curl -fsSL --max-time 30 -D "${headers}" -o "${dest}" "${url}" 2>/dev/null; then
        rm -f "${headers}"
        return 1
    fi
    header_value "${headers}" "etag"
    rm -f "${headers}"
}

# Most recent mainline commit (12-char SHA) touching scripts/checkpatch.pl.
# Best-effort; empty on failure.
latest_commit_sha() {
    curl -sSL --max-time 10 \
        "${KERNEL_LOG_BASE}/checkpatch.pl?h=master" 2>/dev/null \
        | grep -oE 'commit/scripts/checkpatch\.pl\?id=[a-f0-9]+' \
        | head -n1 \
        | sed -E 's|.*id=([a-f0-9]{12}).*|\1|'
}

cp_etag=$(download "${KERNEL_RAW_BASE}/checkpatch.pl" "${CHECKPATCH}") || {
    echo "error: failed to download checkpatch.pl from ${KERNEL_RAW_BASE}" >&2
    echo "       check network connectivity to git.kernel.org" >&2
    exit 2
}

# Helper files used by some checkpatch checks; best-effort, checkpatch
# degrades gracefully if they are missing.
download "${KERNEL_RAW_BASE}/spelling.txt"             "${WORKDIR}/spelling.txt"             >/dev/null 2>&1 || true
download "${KERNEL_RAW_BASE}/const_structs.checkpatch" "${WORKDIR}/const_structs.checkpatch" >/dev/null 2>&1 || true

chmod +x "${CHECKPATCH}"

cp_blob=$(printf '%s' "${cp_etag}" | grep -oE '[a-f0-9]{40}' | head -c 12)
cp_commit=$(latest_commit_sha)

echo "checkpatch: blob ${cp_blob:-unknown} (freshly downloaded from mainline)"
echo "source:     ${KERNEL_RAW_BASE}/checkpatch.pl"
if [ -n "${cp_commit}" ]; then
    echo "mainline:   last touched in commit ${cp_commit} (https://git.kernel.org/torvalds/c/${cp_commit})"
fi
echo

IGNORE_DEFAULT="FILE_PATH_CHANGES,LINUX_VERSION_CODE,SPLIT_STRING"
IGNORE_CMD="--ignore ${IGNORE_DEFAULT}"

find ${target_dir} \( -name *.c -o -name *.h \) -exec ${CHECKPATCH} ${IGNORE_CMD} --no-tree --strict -q -f {} \;
