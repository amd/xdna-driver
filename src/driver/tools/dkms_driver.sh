#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2023-2024, Advanced Micro Devices, Inc. All rights reserved.
#
# Script to install driver source code and enable DKMS

verbose=0
if [[ "$DKMS_DRIVER_VERBOSE" == "true" ]]; then
	verbose=1
fi

# Sanity check against arguments
if [[ -z $1 || ! -z $2 || ( "--install" != $1 && "--remove" != $1 ) ]]; then
	base=`basename $0`
	echo "Invalid arguments. Available options:"
	echo "        ${base} < --install | --remove >"
	exit 1
fi

# Set up global variables
if [[ -z "${XILINX_XRT}" ]]; then
	echo "XILINX_XRT is not set properly"
	exit 1
fi
DRV_NAME="amdxdna"
DRV_SRC_DIR=${XILINX_XRT}/${DRV_NAME}
DKMS_PKG_NAME=`cat ${DRV_SRC_DIR}/dkms.conf | grep ^PACKAGE_NAME | awk -F= '{print $2}' | tr -d '"'`
DKMS_PKG_VER=`cat ${DRV_SRC_DIR}/dkms.conf | grep ^PACKAGE_VERSION | awk -F= '{print $2}' | tr -d '"'`
DKMS_DRV_DIR_NAME=${DKMS_PKG_NAME}-${DKMS_PKG_VER}
DKMS_DRV_DIR=/usr/src/${DKMS_DRV_DIR_NAME}
DKMS_DRV_MODULE_NAME=${DKMS_PKG_NAME}/${DKMS_PKG_VER}

if [[ $1 == "--install" ]]; then
# Install source code for DKMS
	echo "Installing ${DKMS_DRV_DIR_NAME} from ${DRV_SRC_DIR}..."
	# Create directory per DKMS requirement to host driver source code
	mkdir -p ${DKMS_DRV_DIR}
	if [ $? -ne 0 ]; then
		echo "Failed to create DKMS directory for driver source"
		exit 1
	fi
	# Unzip the source code
	cd ${DKMS_DRV_DIR}
	if [[ $verbose == 1 ]]; then
		tar -xvf ${DRV_SRC_DIR}/${DRV_NAME}.tar.gz
	else
		tar -xf ${DRV_SRC_DIR}/${DRV_NAME}.tar.gz
	fi
	if [ $? -ne 0 ]; then
		echo "Failed to install driver source under ${DKMS_DRV_DIR}"
		exit 1
	fi
	# Copy dkms.conf
	cp ${DRV_SRC_DIR}/dkms.conf .
	# Enable DKMS for the driver
	if [[ $verbose == 1 ]]; then
		dkms install --verbose --force ${DKMS_DRV_MODULE_NAME}
	else
		dkms install --force ${DKMS_DRV_MODULE_NAME}
	fi
	if [ $? -ne 0 ]; then
		echo "Failed to enable DKMS for ${DKMS_DRV_MODULE_NAME}"
		exit 1
	fi
	echo "Successfully intalled and enabled DKMS for ${DKMS_DRV_MODULE_NAME}"
else
# Remove source code from DKMS and clean up
	echo "Removing driver source: ${DKMS_DRV_MODULE_NAME}..."
	# Remove from DKMS
	dkms status | grep ${DKMS_DRV_MODULE_NAME}
	if [[ $? -eq 0 ]]; then
		if [[ $verbose == 1 ]]; then
			dkms remove --verbose --all ${DKMS_DRV_MODULE_NAME}
		else
			dkms remove --all ${DKMS_DRV_MODULE_NAME}
		fi
		if [[ $? -ne 0 ]]; then
			echo "Failed to remove ${DKMS_DRV_MODULE_NAME} from DKMS"
			exit 1
		fi
	fi
	# Remove driver source code
	if [[ -d ${DKMS_DRV_DIR} ]]; then
		rm -rf ${DKMS_DRV_DIR}
	else
		echo "${DKMS_DRV_MODULE_NAME} is not installed, nothing to remove"
		exit 1
	fi
	echo "Successfully removed driver source for ${DKMS_DRV_MODULE_NAME}"
fi
