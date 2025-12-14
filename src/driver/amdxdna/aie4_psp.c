// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/bitfield.h>
#include <linux/slab.h>
#include <linux/iopoll.h>
#include "aie4_pci.h"

#define PSP_STATUS_READY	BIT(31)

/* PSP commands */
#define PSP_VALIDATE		0x01
#define PSP_START		0x02
#define PSP_RELEASE_TMR		0x03
#define PSP_VALIDATE_CERT	0x04

/* PSP special arguments */
#define PSP_START_COPY_FW	0x1

/* PSP response error code */
#define PSP_ERROR_CANCEL	0xFFFF0002
#define PSP_ERROR_BAD_STATE	0xFFFF0007

#define PSP_FW_ALIGN		0x10000
#define PSP_CFW_ALIGN		0x8000
#define PSP_POLL_INTERVAL	20000	/* us */
#define PSP_POLL_TIMEOUT	1000000	/* us */
#define PSP_NOTIFY_INTR		0xD007BE11

#define PSP_REG(p, reg) \
	((p)->psp_regs[reg])

#define PSP_SET_CMD_ARG2(cmd, arg2)	(((cmd) << 24) | (arg2))

struct psp_device {
	struct device	  *dev;
	struct aie4_psp_config conf;
	u32		  fw_buf_sz;
	u64		  fw_paddr;
	void		  *fw_buffer;
	u32		  certfw_buf_sz;
	u64		  certfw_paddr;
	void		  *certfw_buffer;
	void __iomem	  *psp_regs[PSP_MAX_REGS];
};

static inline char *psp_decode_resp(u32 resp)
{
	switch (resp) {
	case PSP_ERROR_CANCEL:
		return "Error cancel";
	case PSP_ERROR_BAD_STATE:
		return "Error bad state";
	default:
		return "Error unknown";
	};
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

int aie4_psp_waitmode_poll(struct psp_device *psp)
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

struct psp_device *aie4_psp_create(struct device *dev, struct aie4_psp_config *conf)
{
	struct psp_device *psp;
	u64 offset;

	psp = devm_kzalloc(dev, sizeof(*psp), GFP_KERNEL);
	if (!psp)
		return NULL;

	psp->dev = dev;
	memcpy(psp->psp_regs, conf->psp_regs, sizeof(psp->psp_regs));

	/* NPU firmware*/
	psp->fw_buf_sz = ALIGN(conf->fw_size, PSP_FW_ALIGN);
	psp->fw_buffer = devm_kmalloc(psp->dev, psp->fw_buf_sz + PSP_FW_ALIGN, GFP_KERNEL);
	if (!psp->fw_buffer) {
		dev_err(psp->dev, "no memory for fw buffer");
		return NULL;
	}

	psp->fw_paddr = virt_to_phys(psp->fw_buffer);
	offset = ALIGN(psp->fw_paddr, PSP_FW_ALIGN) - psp->fw_paddr;
	psp->fw_paddr += offset;
	memcpy(psp->fw_buffer + offset, conf->fw_buf, conf->fw_size);

	/* CERT firmware*/
	psp->certfw_buf_sz = ALIGN(conf->certfw_size, PSP_CFW_ALIGN);
	psp->certfw_buffer = devm_kmalloc(psp->dev, psp->certfw_buf_sz + PSP_CFW_ALIGN, GFP_KERNEL);
	if (!psp->certfw_buffer) {
		dev_err(psp->dev, "no memory for cert fw buffer");
		return NULL;
	}

	psp->certfw_paddr = virt_to_phys(psp->certfw_buffer);
	offset = ALIGN(psp->certfw_paddr, PSP_CFW_ALIGN) - psp->certfw_paddr;
	psp->certfw_paddr += offset;
	memcpy(psp->certfw_buffer + offset, conf->certfw_buf, conf->certfw_size);

	return psp;
}
