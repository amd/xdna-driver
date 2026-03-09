// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 */

#include <linux/auxiliary_bus.h>
#include <linux/module.h>

#include "amdxdna_drv.h"

#define AMDXDNA_VE2_AUX_NAME	"amdxdna_ve2"

static const struct auxiliary_device_id amdxdna_ve2_aux_id_table[] = {
	{ .name = AMDXDNA_VE2_AUX_NAME },
	{}
};

MODULE_DEVICE_TABLE(auxiliary, amdxdna_ve2_aux_id_table);

static int amdxdna_ve2_aux_probe(struct auxiliary_device *auxdev,
				 const struct auxiliary_device_id *id)
{
	/* Placeholder: full VE2 DRM accel device init to be implemented */
	return -ENODEV;
}

static void amdxdna_ve2_aux_remove(struct auxiliary_device *auxdev)
{
	/* Placeholder: full VE2 device teardown to be implemented */
}

static struct auxiliary_driver amdxdna_ve2_aux_driver = {
	.name	= AMDXDNA_VE2_AUX_NAME,
	.probe	= amdxdna_ve2_aux_probe,
	.remove	= amdxdna_ve2_aux_remove,
	.id_table = amdxdna_ve2_aux_id_table,
};

module_auxiliary_driver(amdxdna_ve2_aux_driver);

MODULE_LICENSE(AMDXDNA_MODULE_LICENSE);
MODULE_AUTHOR(AMDXDNA_MODULE_AUTHOR);
MODULE_VERSION(AMDXDNA_MODULE_VERSION);
MODULE_DESCRIPTION(AMDXDNA_MODULE_DESCRIPTION);
