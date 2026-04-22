/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_SHMEM_H_
#define _AMDXDNA_SHMEM_H_

#include <linux/platform_device.h>

struct amdxdna_dev;

int amdxdna_shmem_init(struct amdxdna_dev *xdna, struct platform_device *pdev);
void amdxdna_shmem_fini(struct amdxdna_dev *xdna);

#endif /* _AMDXDNA_SHMEM_H_ */
