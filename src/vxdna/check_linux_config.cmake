# SPDX-License-Identifier: MIT
# Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

include(CheckCXXSourceCompiles)

# Check if DRM_IOCTL_SET_CLIENT_NAME is available
check_cxx_source_compiles("
#include <drm/drm.h>
#include <sys/ioctl.h>
int main() {
    struct drm_set_client_name n = {};
    (void)DRM_IOCTL_SET_CLIENT_NAME;
    return 0;
}
" HAVE_DRM_SET_CLIENT_NAME)

if(HAVE_DRM_SET_CLIENT_NAME)
    message(STATUS "DRM_IOCTL_SET_CLIENT_NAME is supported")
else()
    message(STATUS "DRM_IOCTL_SET_CLIENT_NAME is not supported - client name setting will be disabled")
endif()

# Check if struct iovec is defined
check_cxx_source_compiles("
#include <sys/uio.h>
int main() {
    struct iovec iov;
    (void)iov;
    return 0;
}
" HAVE_STRUCT_IOVEC)

if(HAVE_STRUCT_IOVEC)
    message(STATUS "struct iovec is defined in <sys/uio.h>")
else()
    message(WARNING "struct iovec is not defined - IO vector support may be limited")
endif()
