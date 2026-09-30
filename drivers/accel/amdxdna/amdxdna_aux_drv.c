// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Placeholder for auxiliary-bus attachment for AMD XDNA devices.
 * Detailed implementation to be added.
 */

#include <linux/module.h>

#include "amdxdna_aux_drv.h"

int amdxdna_dev_init(struct amdxdna_dev *xdna)
{
	/* TODO: Implementation placeholder */
	return -ENODEV;
}

void amdxdna_dev_cleanup(struct amdxdna_dev *xdna)
{
	/* TODO: Implementation placeholder */
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XRT Team <runtimeca39d@amd.com>");
MODULE_DESCRIPTION("amdxdna auxiliary driver (placeholder)");
