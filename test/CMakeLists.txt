# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

add_subdirectory(shim_test)

# xrt_test exercises the public XRT user API and is only wired up for the
# native (non-VE2) build; the VE2 edge build ships shim_test only.
if(NOT XDNA_VE2)
add_subdirectory(xrt_test)
endif()
