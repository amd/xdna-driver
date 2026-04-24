/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_AUX_DRV_H_
#define _AMDXDNA_AUX_DRV_H_

#include "amdxdna_drv.h"
#include "drm/amdxdna_accel.h"

/*
 * struct amdxdna_dev_info - Device hardware information
 * Record device static information, like reg, mbox, PSP, SMU bar index
 */
struct amdxdna_dev_info {
	int				device_type;
	const struct amdxdna_dev_priv	*dev_priv;
	const struct amdxdna_dev_ops	*ops;
};

/* Add device info below */
extern const struct amdxdna_dev_info dev_ve2_info;

#endif /* _AMDXDNA_AUX_DRV_H_ */
