/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_ERROR_H_
#define _AMDXDNA_ERROR_H_

#include "amdxdna_drm.h"
#include <drm_local/amdxdna_accel.h>
#include <linux/types.h>
#include <linux/mutex.h>

/**
 * AMDXDNA error code layout
 *
 * This layout is internal to AMDXDNA (akin to a POSIX error code).
 *
 * The error code is populated by driver and consumed by AMDXDNA
 * implementation where it is translated into an actual error / info /
 * warning that is propagated to the end user.
 *
 * 63 - 48  47 - 40   39 - 32   31 - 24   23 - 16    15 - 0
 * --------------------------------------------------------
 * |    |    |    |    |    |    |    |    |    |    |----| amdxdna error number
 * |    |    |    |    |    |    |    |    |----|---------- amdxdna error driver
 * |    |    |    |    |    |    |----|-------------------- amdxdna error severity
 * |    |    |    |    |----|------------------------------ amdxdna error module
 * |    |    |----|---------------------------------------- amdxdna error class
 * |----|-------------------------------------------------- reserved
 *
 */

/**
 * amdxdna_error_num - AMDXDNA specific error numbers
 */
enum amdxdna_error_num {
	AMDXDNA_ERROR_NUM_FIRWWALL_TRIP = 1,
	AMDXDNA_ERROR_NUM_TEMP_HIGH,
	AMDXDNA_ERROR_NUM_AIE_SATURATION,
	AMDXDNA_ERROR_NUM_AIE_FP,
	AMDXDNA_ERROR_NUM_AIE_STREAM,
	AMDXDNA_ERROR_NUM_AIE_ACCESS,
	AMDXDNA_ERROR_NUM_AIE_BUS,
	AMDXDNA_ERROR_NUM_AIE_INSTRUCTION,
	AMDXDNA_ERROR_NUM_AIE_ECC,
	AMDXDNA_ERROR_NUM_AIE_LOCK,
	AMDXDNA_ERROR_NUM_AIE_DMA,
	AMDXDNA_ERROR_NUM_AIE_MEM_PARITY,
	AMDXDNA_ERROR_NUM_KDS_CU,
	AMDXDNA_ERROR_NUM_KDS_EXEC,
	AMDXDNA_ERROR_NUM_UNKNOWN
};

enum amdxdna_error_driver {
	AMDXDNA_ERROR_DRIVER_XOCL = 1,
	AMDXDNA_ERROR_DRIVER_XCLMGMT,
	AMDXDNA_ERROR_DRIVER_ZOCL,
	AMDXDNA_ERROR_DRIVER_AIE,
	AMDXDNA_ERROR_DRIVER_UNKNOWN
};

enum amdxdna_error_severity {
	AMDXDNA_ERROR_SEVERITY_EMERGENCY = 1,
	AMDXDNA_ERROR_SEVERITY_ALERT,
	AMDXDNA_ERROR_SEVERITY_CRITICAL,
	AMDXDNA_ERROR_SEVERITY_ERROR,
	AMDXDNA_ERROR_SEVERITY_WARNING,
	AMDXDNA_ERROR_SEVERITY_NOTICE,
	AMDXDNA_ERROR_SEVERITY_INFO,
	AMDXDNA_ERROR_SEVERITY_DEBUG,
	AMDXDNA_ERROR_SEVERITY_UNKNOWN
};

enum amdxdna_error_module {
	AMDXDNA_ERROR_MODULE_FIREWALL = 1,
	AMDXDNA_ERROR_MODULE_CMC,
	AMDXDNA_ERROR_MODULE_AIE_CORE,
	AMDXDNA_ERROR_MODULE_AIE_MEMORY,
	AMDXDNA_ERROR_MODULE_AIE_SHIM,
	AMDXDNA_ERROR_MODULE_AIE_NOC,
	AMDXDNA_ERROR_MODULE_AIE_PL,
	AMDXDNA_ERROR_MODULE_UNKNOWN
};

enum amdxdna_error_class {
	AMDXDNA_ERROR_CLASS_FIRST_ENTRY = 1,
	AMDXDNA_ERROR_CLASS_SYSTEM = AMDXDNA_ERROR_CLASS_FIRST_ENTRY,
	AMDXDNA_ERROR_CLASS_AIE,
	AMDXDNA_ERROR_CLASS_HARDWARE,
	AMDXDNA_ERROR_CLASS_UNKNOWN,
	AMDXDNA_ERROR_CLASS_LAST_ENTRY = AMDXDNA_ERROR_CLASS_UNKNOWN
};

#define AMDXDNA_ERROR_NUM_MASK		0xFFFFUL
#define AMDXDNA_ERROR_NUM_SHIFT		0
#define AMDXDNA_ERROR_DRIVER_MASK		0xFUL
#define AMDXDNA_ERROR_DRIVER_SHIFT		16
#define AMDXDNA_ERROR_SEVERITY_MASK		0xFUL
#define AMDXDNA_ERROR_SEVERITY_SHIFT	24
#define AMDXDNA_ERROR_MODULE_MASK		0xFUL
#define AMDXDNA_ERROR_MODULE_SHIFT		32
#define AMDXDNA_ERROR_CLASS_MASK		0xFUL
#define AMDXDNA_ERROR_CLASS_SHIFT		40

#define	AMDXDNA_ERROR_CODE_BUILD(num, driver, severity, module, eclass) \
	((((num) & AMDXDNA_ERROR_NUM_MASK) << AMDXDNA_ERROR_NUM_SHIFT) | \
	(((driver) & AMDXDNA_ERROR_DRIVER_MASK) << AMDXDNA_ERROR_DRIVER_SHIFT) | \
	(((severity) & AMDXDNA_ERROR_SEVERITY_MASK) << AMDXDNA_ERROR_SEVERITY_SHIFT) | \
	(((module) & AMDXDNA_ERROR_MODULE_MASK) << AMDXDNA_ERROR_MODULE_SHIFT) | \
	(((eclass) & AMDXDNA_ERROR_CLASS_MASK) << AMDXDNA_ERROR_CLASS_SHIFT))

#define AMDXDNA_CRITICAL_ERROR_CODE_BUILD(num, module) \
	AMDXDNA_ERROR_CODE_BUILD((num), AMDXDNA_ERROR_DRIVER_AIE, \
	AMDXDNA_ERROR_SEVERITY_CRITICAL, (module), AMDXDNA_ERROR_CLASS_AIE)

struct amdxdna_async_err_cache {
	struct amdxdna_async_error err; /* last async error which can be queried from userspace */
	struct mutex lock; /* protects access to the error cache */
};

/**
 * AMDXDNA extra error code layout
 *
 * The error code is populated by driver and propagated to the end user
 *
 * 63 - - - - - - - - - - - - - - - - - - - -  15 -  8 -  0
 * --------------------------------------------------------
 * |                                            |    |----| error location AIE tile column
 * |                                            |---------- error location AIE tile row
 * |------------------------------------------------------- reserved
 *
 */

#define AMDXDNA_ERROR_EXTRA_CODE_COL_MASK  0xFUL
#define AMDXDNA_ERROR_EXTRA_CODE_COL_SHIFT 0
#define AMDXDNA_ERROR_EXTRA_CODE_ROW_MASK  0xFUL
#define AMDXDNA_ERROR_EXTRA_CODE_ROW_SHIFT 8
#define AMDXDNA_ERROR_EXTRA_CODE_BUILD(row, col) \
	((((col) & AMDXDNA_ERROR_EXTRA_CODE_COL_MASK) << AMDXDNA_ERROR_EXTRA_CODE_COL_SHIFT) | \
	(((row) & AMDXDNA_ERROR_EXTRA_CODE_ROW_MASK) << AMDXDNA_ERROR_EXTRA_CODE_ROW_SHIFT))

#endif /* _AMDXDNA_ERROR_H_ */
