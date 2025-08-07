/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_PM_H_
#define _AMDXDNA_PM_H_

#include <linux/pm_runtime.h>
#include "amdxdna_drm.h"

extern const struct dev_pm_ops amdxdna_pm_ops;

int amdxdna_pm_resume_get(struct amdxdna_dev *xdna);
void amdxdna_pm_suspend_put(struct amdxdna_dev *xdna);
void amdxdna_rpm_init(struct amdxdna_dev *xdna);
void amdxdna_rpm_fini(struct amdxdna_dev *xdna);

#endif /* _AMDXDNA_PM_H_ */
