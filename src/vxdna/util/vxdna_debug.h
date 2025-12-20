// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

/**
 * @file vxdna_debug.h
 * @brief Debug and logging utilities for VXDNA
 *
 * Provides logging functions with different severity levels and
 * consistent [VXDNA] prefix.
 */

#ifndef VXDNA_DEBUG_H
#define VXDNA_DEBUG_H

#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Log level enumeration
 */
enum vxdna_log_level {
    VXDNA_LOG_ERROR = 0,   /**< Error messages (always shown) */
    VXDNA_LOG_INFO  = 1,   /**< Informational messages */
    VXDNA_LOG_DEBUG = 2,   /**< Debug messages (only when enabled) */
};

/**
 * @brief Set global log level
 *
 * Messages with level higher than this will be suppressed.
 * Default is VXDNA_LOG_INFO.
 *
 * @param level Maximum log level to display
 */
void vxdna_set_log_level(enum vxdna_log_level level);

/**
 * @brief Get current log level
 *
 * @return Current log level setting
 */
enum vxdna_log_level vxdna_get_log_level(void);

/**
 * @brief Generic logging function
 *
 * Internal function used by convenience wrappers.
 *
 * @param level Log level
 * @param fmt Printf-style format string
 * @param ... Variable arguments
 */
void vxdna_log(enum vxdna_log_level level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/**
 * @brief Log an error message
 *
 * Error messages are always displayed regardless of log level.
 * Format: [VXDNA] ERROR: <message>
 *
 * @param fmt Printf-style format string
 * @param ... Variable arguments
 */
static inline void vxdna_err(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

static inline void vxdna_err(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[VXDNA] ERROR: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/**
 * @brief Log an informational message
 *
 * Displayed when log level >= VXDNA_LOG_INFO.
 * Format: [VXDNA] INFO: <message>
 *
 * @param fmt Printf-style format string
 * @param ... Variable arguments
 */
#define vxdna_info(fmt, ...) \
    vxdna_log(VXDNA_LOG_INFO, fmt, ##__VA_ARGS__)

/**
 * @brief Log a debug message
 *
 * Displayed when log level >= VXDNA_LOG_DEBUG.
 * Format: [VXDNA] DEBUG: <message>
 *
 * @param fmt Printf-style format string
 * @param ... Variable arguments
 */
#define vxdna_dbg(fmt, ...) \
    vxdna_log(VXDNA_LOG_DEBUG, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* VXDNA_DEBUG_H */

