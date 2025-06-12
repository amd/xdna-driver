# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022-2025, Advanced Micro Devices, Inc. All rights reserved.

if(XDNA_VE2)
add_subdirectory(shim_ve2)
else()
add_subdirectory(driver)
add_subdirectory(shim)
endif()
