/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 always-on trace (drm_info). Enable with module param ve2_trace.
 */

#ifndef _VE2_TRACE_H_
#define _VE2_TRACE_H_

#include "amdxdna_drv.h"

/*
 * ve2_trace levels:
 *   0 - off (default)
 *   1 - ioctl / hwctx / submit / wait boundaries
 *   2 - verbose (AIE schedule, IRQ, polling timer samples)
 */
extern int ve2_trace;

#define VE2_TRACE(xdna, fmt, args...)					\
	do {								\
		if (ve2_trace >= 1)					\
			drm_info(&(xdna)->ddev, "VE2: " fmt, ##args);	\
	} while (0)

#define VE2_TRACE2(xdna, fmt, args...)					\
	do {								\
		if (ve2_trace >= 2)					\
			drm_info(&(xdna)->ddev, "VE2: " fmt, ##args);	\
	} while (0)

#endif /* _VE2_TRACE_H_ */
