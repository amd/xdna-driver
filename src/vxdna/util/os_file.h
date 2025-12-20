// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

/**
 * @file os_file.h
 * @brief OS-specific file descriptor utilities
 */

#ifndef VXDNA_OS_FILE_H
#define VXDNA_OS_FILE_H

/**
 * @brief Duplicate file descriptor with close-on-exec flag
 *
 * Creates a duplicate of the given file descriptor with the close-on-exec
 * flag set. This ensures the FD is not leaked to child processes.
 *
 * Uses F_DUPFD_CLOEXEC if available, otherwise falls back to dup() + fcntl().
 *
 * @param fd File descriptor to duplicate
 * @return New file descriptor on success, -1 on failure
 *
 * @note Caller is responsible for closing the returned file descriptor
 *
 * @see dup(2), fcntl(2)
 */
int os_dupfd_cloexec(int fd);

#endif /* VXDNA_OS_FILE_H */
