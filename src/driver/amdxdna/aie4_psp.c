// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 */

#include <linux/bitfield.h>
#include <linux/slab.h>
#include <linux/iopoll.h>
#include "aie4_pci.h"

#define PSP_SET_CMD_ARG2(cmd, arg2)	(((cmd) << 24) | (arg2))

static inline char *psp_decode_resp(u32 resp)
{
	switch (resp) {
	case PSP_ERROR_CANCEL:
		return "Error cancel";
	case PSP_ERROR_BAD_STATE:
		return "Error bad state";
	default:
		break;
	}

	return "Error unknown";
}

static int psp_exec(struct psp_device *psp, u32 *reg_vals)
{
	u32 resp_code;
	int ret, i;
	u32 ready;

	/* Check for PSP ready before any write */
	ret = readx_poll_timeout(readl, PSP_REG(psp, PSP_STATUS_REG), ready,
				 FIELD_GET(PSP_STATUS_READY, ready),
				 PSP_POLL_INTERVAL, PSP_POLL_TIMEOUT);
	if (ret) {
		dev_err(psp->dev, "PSP is not ready, ret 0x%x", ret);
		return ret;
	}

	/* Write command and argument registers */
	for (i = 1; i < PSP_NUM_IN_REGS; i++)
		writel(reg_vals[i], PSP_REG(psp, i));

	/* clear and set PSP INTR register to kick off */
	writel(0, PSP_REG(psp, PSP_INTR_REG));
	writel(PSP_NOTIFY_INTR, PSP_REG(psp, PSP_INTR_REG));

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
		dev_err(psp->dev, "fw return error 0x%x (%s)", resp_code,
			psp_decode_resp(resp_code));
		return -EIO;
	}

	return 0;
}

void aie4_psp_stop(struct psp_device *psp)
{
	u32 reg_vals[PSP_NUM_IN_REGS];
	int ret;

	memset(reg_vals, 0, sizeof(reg_vals));
	reg_vals[3] = PSP_SET_CMD_ARG2(PSP_RELEASE_TMR, 0);

	ret = psp_exec(psp, reg_vals);
	if (ret)
		dev_err(psp->dev, "release tmr failed, ret %d", ret);
	else
		dev_dbg(psp->dev, "release tmr successful");
}

int aie4_psp_start(struct psp_device *psp)
{
	u32 reg_vals[PSP_NUM_IN_REGS];
	int ret;

	/* NPU firmware*/
	reg_vals[0] = PSP_VALIDATE;
	reg_vals[1] = lower_32_bits(psp->fw_paddr);
	reg_vals[2] = upper_32_bits(psp->fw_paddr);
	reg_vals[3] = PSP_SET_CMD_ARG2(PSP_VALIDATE, psp->fw_buf_sz);

	ret = psp_exec(psp, reg_vals);
	if (ret) {
		dev_err(psp->dev, "failed to validate fw, ret %d", ret);
		return ret;
	}

	/* CERT firmware*/
	reg_vals[0] = PSP_VALIDATE_CERT;
	reg_vals[1] = lower_32_bits(psp->certfw_paddr);
	reg_vals[2] = upper_32_bits(psp->certfw_paddr);
	reg_vals[3] = PSP_SET_CMD_ARG2(PSP_VALIDATE_CERT, psp->certfw_buf_sz);

	ret = psp_exec(psp, reg_vals);
	if (ret) {
		dev_err(psp->dev, "failed to validate cert fw, ret %d", ret);
		return ret;
	}

	/* Start execution NPU/CERT firmwares */
	memset(reg_vals, 0, sizeof(reg_vals));
	reg_vals[1] = PSP_START_COPY_FW;
	reg_vals[3] = PSP_SET_CMD_ARG2(PSP_START, 0);

	ret = psp_exec(psp, reg_vals);
	if (ret) {
		dev_err(psp->dev, "failed to start cert fw, ret %d", ret);
		return ret;
	}

	dev_dbg(psp->dev, "successfully download mpnpu and cert fw");
	return 0;
}
