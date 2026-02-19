#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.
#
# DKMS PRE_BUILD wrapper script

# Fix Kbuild include paths for DKMS structure
sed -i 's|\.\./\.\./include/uapi|../include/uapi|g' amdxdna/Kbuild
sed -i 's|\.\./\.\./include$|../include|g' amdxdna/Kbuild

# Generate config_kernel.h
OUT=amdxdna/config_kernel.h ./configure_kernel.sh
