// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

/*
 * OS File Utilities Implementation
 */

#include "os_file.h"
#include <unistd.h>

#ifndef WIN32
#include <fcntl.h>
#endif

/* Duplicate file descriptor with close-on-exec flag */
int
os_dupfd_cloexec(int fd)
{
    if (fd < 0)
        return -1;

#ifdef F_DUPFD_CLOEXEC
    return fcntl(fd, F_DUPFD_CLOEXEC, 0);
#else
    int new_fd = dup(fd);
    if (new_fd >= 0) {
        int ret = fcntl(new_fd, F_SETFD, FD_CLOEXEC);
        if (ret < 0) {
            ret = -errno;
            close(new_fd);
            return ret;
        }
    }
    return new_fd;
#endif
}

