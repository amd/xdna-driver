/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _VE2_OF_H_
#define _VE2_OF_H_

#include "amdxdna_of_drv.h"

struct amdxdna_dev_priv {
	const char                      *fw_path;
};

struct amdxdna_dev_hdl {
	struct amdxdna_dev              *xdna;
	const struct amdxdna_dev_priv   *priv;
};

/* ve2_of.c */
extern const struct amdxdna_dev_ops ve2_ops;

#endif /* _VE2_OF_H_ */
