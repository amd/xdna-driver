#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Download all firmware files from info.json for DKMS package

set -e

INFO_JSON="${1:-tools/info.json}"
FIRMWARE_DIR="${2:-amdxdna_bins/firmware}"

if [ ! -f "$INFO_JSON" ]; then
    echo "Error: info.json not found at $INFO_JSON"
    exit 1
fi

mkdir -p "$FIRMWARE_DIR"

echo "Downloading all firmware files for DKMS package..."

jq -c '.firmwares[]' "$INFO_JSON" |
  while IFS= read -r line; do
    device=$(echo $line | jq -r '.device')
    pci_dev_id=$(echo $line | jq -r '.pci_device_id')
    version=$(echo $line | jq -r '.version')
    fw_name=$(echo $line | jq -r '.fw_name')
    url=$(echo $line | jq -r '.url')
    pci_rev_id=$(echo $line | jq -r '.pci_revision_id')

    if [[ -z "$url" ]]; then
      echo "Empty URL for $device firmware, SKIP."
      continue
    fi

    target_dir="${FIRMWARE_DIR}/${pci_dev_id}_${pci_rev_id}"
    target_file="${target_dir}/${fw_name}"

    if [ -f "$target_file" ]; then
      echo "  $device ($pci_dev_id:$pci_rev_id): Already exists, skipping"
      continue
    fi

    echo "  $device ($pci_dev_id:$pci_rev_id) v$version: Downloading..."
    mkdir -p "$target_dir"

    if wget -q -O "$target_file" "$url"; then
      echo "    ✓ Downloaded to $target_file"
    else
      echo "    ✗ Failed to download from $url"
      rm -f "$target_file"
    fi
  done

echo ""
echo "Firmware download complete!"
echo "Downloaded to: $FIRMWARE_DIR"
ls -lR "$FIRMWARE_DIR" | grep "^-" | wc -l | xargs echo "Total files:"
