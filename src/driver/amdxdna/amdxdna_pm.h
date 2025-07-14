/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_PM_H_
#define _AMDXDNA_PM_H_

#include <linux/pm.h>

extern const struct dev_pm_ops amdxdna_pm_ops;

int amdxdna_pm_resume_get(struct device *dev);
void amdxdna_pm_suspend_put(struct device *dev);
void amdxdna_pm_init(struct device *dev);
void amdxdna_pm_fini(struct device *dev);

#endif /* _AMDXDNA_PM_H_ */
