/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_AUX_DRV_H_
#define _AMDXDNA_AUX_DRV_H_

#include "amdxdna_pci_drv.h"

int amdxdna_dev_init(struct amdxdna_dev *xdna);
void amdxdna_dev_cleanup(struct amdxdna_dev *xdna);

#endif /* _AMDXDNA_AUX_DRV_H_ */
