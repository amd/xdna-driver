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
#
# Usage:
#   codingsty_check.sh <PATH> [PATH ...]
#
# Each PATH may be a directory (scanned recursively for *.c and *.h) or an
# individual *.c/*.h file (other file types are skipped). The script exits
# non-zero if checkpatch reports any error or warning on any scanned file, so
# it can gate a CI job or pre-commit hook.

set -u

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <PATH> [PATH ...]   (each PATH may be a file or a directory)" >&2
    exit 2
fi

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

# Expand the given paths into a flat list of C source and header files. A
# non-existent path is a caller error (misconfigured CI job or hook), not a
# reason to silently skip checks, so it fails the run rather than warning.
files=()
missing=0
for path in "$@"; do
    if [ -d "${path}" ]; then
        while IFS= read -r f; do
            files+=("${f}")
        done < <(find "${path}" \( -name '*.c' -o -name '*.h' \) -type f)
    elif [ -f "${path}" ]; then
        case "${path}" in
            *.c|*.h) files+=("${path}") ;;
            *) echo "warning: skipping '${path}' (not a .c or .h file)" >&2 ;;
        esac
    else
        echo "error: path does not exist: '${path}'" >&2
        missing=1
    fi
done

if [ "${missing}" -ne 0 ]; then
    echo "error: one or more input paths did not exist; refusing to skip checks" >&2
    exit 2
fi

if [ "${#files[@]}" -eq 0 ]; then
    echo "no C source or header files to check"
    exit 0
fi

fail=0
for f in "${files[@]}"; do
    "${CHECKPATCH}" ${IGNORE_CMD} --no-tree --strict -q -f "${f}" || fail=1
done

exit ${fail}
