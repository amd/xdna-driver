#! /bin/bash -

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
#

SCRIPT_DIR=$(readlink -f $(dirname ${BASH_SOURCE[0]}))

if [ -x "$(command -v apt-get)" ]; then
    apt-get install -y jq
elif [ -x "$(command -v dnf)" ]; then
    dnf install -y jq
elif [ -x "$(command -v pacman)" ]; then
    pacman -Syu --needed --noconfirm jq
fi

$SCRIPT_DIR/../xrt/src/runtime_src/tools/scripts/xrtdeps.sh
