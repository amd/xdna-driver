// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include "ve2_of.h"

static int ve2_init(struct amdxdna_dev *xdna)
{
	struct platform_device *pdev = to_platform_device(xdna->ddev.dev);
	struct amdxdna_dev_hdl *xdna_hdl = NULL;

	xdna_hdl = devm_kzalloc(&pdev->dev, sizeof(*xdna_hdl), GFP_KERNEL);
	if (!xdna_hdl)
		return -ENOMEM;

	xdna_hdl->xdna = xdna;

	xdna->dev_handle = xdna_hdl;

	return 0;
}

static void ve2_fini(struct amdxdna_dev *xdna)
{
}

const struct amdxdna_dev_ops ve2_ops = {
	.init		= ve2_init,
	.fini		= ve2_fini,
};
