/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_SYSFS_H_
#define _AMDXDNA_SYSFS_H_

#include "amdxdna_drm.h"

int amdxdna_sysfs_init(struct amdxdna_dev *xdna);
void amdxdna_sysfs_fini(struct amdxdna_dev *xdna);

#endif /* _AMDXDNA_SYSFS_H_ */
