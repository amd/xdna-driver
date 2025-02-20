#! /bin/bash --

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025, Advanced Micro Devices, Inc.
#

CHECKPATCH=/lib/modules/$(uname -r)/build/scripts/checkpatch.pl
target_dir=$1

if [ -f ${CHECKPATCH} ]; then
    echo "run check patch: ${CHECKPATCH}"
else
    echo "checkpatch script not found: ${CHECKPATCH}"
    exit 2
fi

IGNORE_DEFAULT="FILE_PATH_CHANGES,LINUX_VERSION_CODE,SPLIT_STRING"
IGNORE_CMD="--ignore ${IGNORE_DEFAULT}"

find ${target_dir} \( -name *.c -o -name *.h \) -exec ${CHECKPATCH} ${IGNORE_CMD} --no-tree --strict -q -f {} \;
