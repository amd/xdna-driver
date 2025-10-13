# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.
if (POLICY CMP0177)
  cmake_policy(SET CMP0177 NEW)
endif()

# When building for upstream, only shim plugin library is built
# XRT is part of the upstreaming project and provides the headers
# and targets needed by xdna plugin
set(XRT_PLUGIN_VERSION_STRING ${XRT_VERSION_STRING})
add_subdirectory(src/shim)
