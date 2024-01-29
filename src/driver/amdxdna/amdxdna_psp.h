/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef __AMDXDNA_PSP_H__
#define __AMDXDNA_PSP_H__

#include <linux/device.h>
#include <linux/io.h>

struct psp_device;

/* Don't change the order in this enum */
enum psp_reg_idx {
	PSP_CMD_REG = 0,
	PSP_ARG0_REG,
	PSP_ARG1_REG,
	PSP_ARG2_REG,
	PSP_NUM_IN_REGS, /* number of input registers */
	PSP_INTR_REG = PSP_NUM_IN_REGS,
	PSP_STATUS_REG,
	PSP_RESP_REG,
	PSP_MAX_REGS /* Keep this at the end */
};

struct psp_config {
	const void	*fw_buf;
	u32		fw_size;
	void __iomem	*psp_regs[PSP_MAX_REGS];
};

struct psp_device *amdxdna_psp_create(struct device *dev, struct psp_config *conf);
void amdxdna_psp_remove(struct psp_device *psp);
#endif /* __AMDXDNA_PSP_H__ */
