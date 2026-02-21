#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copy firmware files if available

FIRMWARE_SRC="$1"
FIRMWARE_DST="$2"

if [ -d "$FIRMWARE_SRC" ]; then
    cp -r "$FIRMWARE_SRC" "$FIRMWARE_DST"
    echo "Firmware included in package from $FIRMWARE_SRC"
else
    echo "Warning: Firmware not found at $FIRMWARE_SRC - package will not include firmware"
fi
