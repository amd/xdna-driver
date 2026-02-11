// SPDX-License-Identifier: MIT
// Copyright (C) 2025 - 2026, Advanced Micro Devices, Inc. All rights reserved.

/**
 * @file vxdna_debug.cpp
 * @brief Implementation of debug and logging utilities
 */

#include "vxdna_debug.h"
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>

/* Global log level - default to INFO */
static enum vxdna_log_level g_log_level = VXDNA_LOG_INFO;

/* Check if logging is initialized from environment */
static int g_log_initialized = 0;

/**
 * @brief Initialize logging from environment variables
 *
 * Checks VXDNA_LOG_LEVEL environment variable:
 * - "ERROR" or "0" -> VXDNA_LOG_ERROR
 * - "INFO" or "1"  -> VXDNA_LOG_INFO
 * - "DEBUG" or "2" -> VXDNA_LOG_DEBUG
 */
static void
vxdna_log_init(void)
{
    const char *env_level;

    if (g_log_initialized)
        return;

    g_log_initialized = 1;

    env_level = getenv("VXDNA_LOG_LEVEL");
    if (!env_level)
        return;

    if (strcmp(env_level, "ERROR") == 0 || strcmp(env_level, "0") == 0) {
        g_log_level = VXDNA_LOG_ERROR;
    } else if (strcmp(env_level, "INFO") == 0 || strcmp(env_level, "1") == 0) {
        g_log_level = VXDNA_LOG_INFO;
    } else if (strcmp(env_level, "DEBUG") == 0 || strcmp(env_level, "2") == 0) {
        g_log_level = VXDNA_LOG_DEBUG;
    }
}

void
vxdna_set_log_level(enum vxdna_log_level level)
{
    g_log_level = level;
}

enum vxdna_log_level
vxdna_get_log_level(void)
{
    if (!g_log_initialized)
        vxdna_log_init();

    return g_log_level;
}

void
vxdna_log(enum vxdna_log_level level, const char *fmt, ...)
{
    va_list args;
    const char *level_str;
    FILE *output;

    /* Initialize logging on first use */
    if (!g_log_initialized)
        vxdna_log_init();

    /* Check if this message should be displayed */
    if (level > g_log_level)
        return;

    /* Select output stream and level string */
    switch (level) {
    case VXDNA_LOG_ERROR:
        level_str = "ERROR";
        output = stderr;
        break;
    case VXDNA_LOG_INFO:
        level_str = "INFO";
        output = stdout;
        break;
    case VXDNA_LOG_DEBUG:
        level_str = "DEBUG";
        output = stdout;
        break;
    default:
        level_str = "UNKNOWN";
        output = stdout;
        break;
    }

    /* Print message with prefix */
    fprintf(output, "[VXDNA] %s: ", level_str);
    va_start(args, fmt);
    vfprintf(output, fmt, args);
    va_end(args);
    fprintf(output, "\n");
    fflush(output);
}

