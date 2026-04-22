/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_RPMSG_H_
#define _AMDXDNA_RPMSG_H_

#include <linux/of.h>

struct amdxdna_dev;

int amdxdna_rpmsg_init(struct amdxdna_dev *xdna, struct device_node *np);
void amdxdna_rpmsg_fini(struct amdxdna_dev *xdna);

#endif /* _AMDXDNA_RPMSG_H_ */
