// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 */

#include <linux/bitfield.h>
#include <linux/slab.h>
#include <linux/iopoll.h>
#include "aie2_pci.h"
#include "amdxdna_xen.h"

static int psp_exec(struct psp_device *psp, u32 *reg_vals)
{
	u32 resp_code;
	int ret, i;
	u32 ready;

	/* Write command and argument registers */
	for (i = 0; i < PSP_NUM_IN_REGS; i++)
		writel(reg_vals[i], PSP_REG(psp, i));

	/* clear and set PSP INTR register to kick off */
	writel(0, PSP_REG(psp, PSP_INTR_REG));
	writel(1, PSP_REG(psp, PSP_INTR_REG));

	/* PSP should be busy. Wait for ready, so we know task is done. */
	ret = readx_poll_timeout(readl, PSP_REG(psp, PSP_STATUS_REG), ready,
				 FIELD_GET(PSP_STATUS_READY, ready),
				 PSP_POLL_INTERVAL, PSP_POLL_TIMEOUT);
	if (ret) {
		dev_err(psp->dev, "PSP is not ready, ret 0x%x", ret);
		return ret;
	}

	resp_code = readl(PSP_REG(psp, PSP_RESP_REG));
	if (resp_code) {
		dev_err(psp->dev, "fw return error 0x%x(%s)", resp_code,
			psp_decode_resp(resp_code));
		return -EIO;
	}

	return 0;
}

void aie2_psp_stop(struct psp_device *psp)
{
	u32 reg_vals[PSP_NUM_IN_REGS] = { PSP_RELEASE_TMR, };
	int ret;

	ret = psp_exec(psp, reg_vals);
	if (ret)
		dev_err(psp->dev, "release tmr failed, ret %d", ret);
}

int aie2_psp_waitmode_poll(struct psp_device *psp)
{
	int mode_reg = -1, ret;

	ret = readx_poll_timeout(readl, PSP_REG(psp, PSP_PWAITMODE_REG), mode_reg,
				 (mode_reg & 0x1) == 1,
				 PSP_POLL_INTERVAL, PSP_POLL_TIMEOUT);
	if (ret) {
		dev_err(psp->dev, "fw waitmode reg error, ret 0x%x", ret);
		return ret;
	}

	return 0;
}

void aie2_psp_destroy(struct device *dev, struct psp_device *psp)
{
	if (is_xen_initial_pvh_domain())
		amdxdna_xen_free_buf_phys(dev, psp->fw_buffer, psp->fw_dma_handle,
					  psp->fw_buf_sz + PSP_FW_ALIGN);
}

int aie2_psp_start(struct psp_device *psp)
{
	u32 reg_vals[PSP_NUM_IN_REGS];
	int ret;

	reg_vals[0] = PSP_VALIDATE;
	reg_vals[1] = lower_32_bits(psp->fw_paddr);
	reg_vals[2] = upper_32_bits(psp->fw_paddr);
	reg_vals[3] = psp->fw_buf_sz;

	ret = psp_exec(psp, reg_vals);
	if (ret) {
		dev_err(psp->dev, "failed to validate fw, ret %d", ret);
		return ret;
	}

	memset(reg_vals, 0, sizeof(reg_vals));
	reg_vals[0] = PSP_START;
	reg_vals[1] = PSP_START_COPY_FW;
	ret = psp_exec(psp, reg_vals);
	if (ret) {
		dev_err(psp->dev, "failed to start fw, ret %d", ret);
		return ret;
	}

	return 0;
}

