#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023-2024 Advanced Micro Devices, Inc. All rights reserved.
#
# Script to install driver source code and enable DKMS

declare -A devices

devices["Phoenix"]="1502"
devices["IPU2"]="17f0"

usage()
{
	cat << USAGE_END
Usage: sudo setup_xclbin_firmware.sh [options]
Options:
	-help				Display this help
	-dev <device name>	IPU Device VBNV
	-xclbin	<xclbin>	xclbin to install
	-list				List supported devices
	-clean				cleanup binary and symbolic link
	-verbose			verbose message
USAGE_END
}

get_xclbin_uuid()
{
	local xclbin="$1"

	${XILINX_XRT}/bin/xclbinutil --info -i $xclbin | grep "UUID (xclbin)" | awk '{print $3}'
}

create_link()
{
	local dir="$1"

	orig_dir=`pwd`
	cd $dir

	for xclbin_file in *.xclbin; do
		if [ -f "$xclbin_file" ]; then
			xclbin_uuid=`get_xclbin_uuid $xclbin_file`
			if [ -e "${xclbin_uuid}.xclbin" ]; then
				continue
			fi
			ln -f -s "$xclbin_file" "${xclbin_uuid}.xclbin"
		fi
	done

	cd $orig_dir
}

# Set up global variables
if [[ -z "${XILINX_XRT}" ]]; then
	echo "XILINX_XRT is not set properly"
	exit 1
fi

dev=""
xclbin=""
verbose=0
clean=0
list=0

while [ $# -gt 0 ]; do
	case "$1" in
		-help | -h)
			usage
			exit 0
			;;
		-dev | -d)
			dev=$2
			shift
			;;
		-xclbin | -x)
			xclbin=$2
			shift
			;;
		-clean | -c)
			clean=1
			;;
		-verbose | -v)
			verbose=1
			;;
		-list | -l)
			list=1
			;;
		*)
			echo "unknown option"
			;;
	esac
	shift
done

AMDXDNA_FIRMWARE_DIR=/lib/firmware/amdipu

if [ "$verbose" == 1 ]; then
	echo "===== Debug ====="
	set -x
fi

if [[ $clean != 0 ]]; then
	find ${AMDXDNA_FIRMWARE_DIR} -type l -exec rm {} \;
	find ${AMDXDNA_FIRMWARE_DIR} -name *_unsigned.xclbin -exec rm {} \;
	exit 0
fi

if [ "$list" = 1 ]; then
	echo ${!devices[@]} | tr ' ' '\n'
	exit 0
fi

if [[ "$EUID" != 0 ]]; then
	echo "!!! Please run as root !!!"
	echo -e "$ sudo bash \nor sudo <other shell>"
	exit 1
fi

if [ ! -z "$xclbin" ]; then
	if [ -z "$dev" ]; then
		echo "[ERROR] -dev option is not specified"
		exit 1
	fi

	dev_id=${devices["$dev"]}
	if [[ -z "${dev_id}" ]]; then
		echo "[ERROR] '$dev' not in the list: '${!devices[@]}' "
		exit 1
	fi

	if [ ! -d "${AMDXDNA_FIRMWARE_DIR}/$dev_id" ]; then
		echo "[ERROR] ${AMDXDNA_FIRMWARE_DIR}/$dev_id not exist"
		exit 1
	fi

	if [ ! -f "$xclbin" ]; then
		echo "[ERROR] $xclbin not exist"
		exit 1
	fi

	${XILINX_XRT}/bin/xclbinutil -i "$xclbin" >> /dev/null
	if [[ "$?" != 0 ]]; then
		echo "[ERROR] xclbinutil does not recognize $xclbin"
		exit 1
	fi

	xclbin_name=$(basename $xclbin)
	echo "Copy $xclbin to ${AMDXDNA_FIRMWARE_DIR}/$dev_id/${xclbin_name%.*}_unsigned.xclbin"
	cp -f $xclbin ${AMDXDNA_FIRMWARE_DIR}/$dev_id/${xclbin_name%.*}_unsigned.xclbin
fi

for subdir in ${AMDXDNA_FIRMWARE_DIR}/*/; do
	create_link $subdir
done

if [ "$verbose" = 1 ]; then
	echo "========= Debug end ========="
	set +x
fi
