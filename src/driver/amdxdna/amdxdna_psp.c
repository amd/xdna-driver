// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2022-2024 Advanced Micro Devices, Inc.
 */

#include <linux/bitfield.h>
#include <linux/slab.h>
#include <linux/iopoll.h>
#include <linux/firmware.h>
#include "amdxdna_psp.h"

#define PSP_STATUS_READY	BIT(31)

/* PSP commands */
#define PSP_VALIDATE		1
#define PSP_START		2
#define PSP_RELEASE_TMR		3

/* PSP special arguments */
#define PSP_START_COPY_FW	1

/* PSP response error code */
#define PSP_ERROR_CANCEL	0xFFFF0002
#define PSP_ERROR_BAD_STATE	0xFFFF0007

#define PSP_FW_ALIGN		0x10000
#define PSP_POLL_INTERVAL	20000	/* us */
#define PSP_POLL_TIMEOUT	1000000	/* us */

#define PSP_REG(p, reg) \
	((p)->conf.psp_regs[reg])

struct psp_device {
	struct device	  *dev;
	struct psp_config conf;
	void		  *fw_buffer;
	u64		  fw_paddr;
	u32		  fw_buf_sz;
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

static int psp_load_firmware(struct psp_device *psp)
{
	const struct firmware *fw;
	u64 offset;
	int ret;

	ret = request_firmware(&fw, psp->conf.fw_path, psp->dev);
	if (ret) {
		dev_err(psp->dev, "failed to request_firmware %s, error = %d",
			psp->conf.fw_path, ret);
		return ret;
	}

	psp->fw_buf_sz = ALIGN(fw->size, PSP_FW_ALIGN) + PSP_FW_ALIGN;
	psp->fw_buffer = devm_kmalloc(psp->dev, psp->fw_buf_sz, GFP_KERNEL);
	if (!psp->fw_buffer) {
		ret = -ENOMEM;
		goto failed;
	}

	psp->fw_paddr = virt_to_phys(psp->fw_buffer);
	offset = ALIGN(psp->fw_paddr, PSP_FW_ALIGN) - psp->fw_paddr;
	psp->fw_paddr += offset;
	memcpy(psp->fw_buffer + offset, fw->data, fw->size);

failed:
	release_firmware(fw);
	return ret;
}

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

void amdxdna_psp_remove(struct psp_device *psp)
{
	u32 reg_vals[PSP_NUM_IN_REGS] = { PSP_RELEASE_TMR, };
	int ret;

	ret = psp_exec(psp, reg_vals);
	if (ret)
		dev_err(psp->dev, "release tmr failed, ret %d", ret);
}

struct psp_device *amdxdna_psp_create(struct device *dev, struct psp_config *conf)
{
	u32 reg_vals[PSP_NUM_IN_REGS];
	struct psp_device *psp;
	int ret;

	psp = devm_kzalloc(dev, sizeof(*psp), GFP_KERNEL);
	if (!psp)
		return NULL;

	psp->dev = dev;
	memcpy(&psp->conf, conf, sizeof(psp->conf));

	ret = psp_load_firmware(psp);
	if (ret) {
		dev_err(psp->dev, "failed to load fw, ret %d", ret);
		return NULL;
	}

	reg_vals[0] = PSP_VALIDATE;
	reg_vals[1] = lower_32_bits(psp->fw_paddr);
	reg_vals[2] = upper_32_bits(psp->fw_paddr);
	reg_vals[3] = psp->fw_buf_sz;

	ret = psp_exec(psp, reg_vals);
	if (ret) {
		dev_err(psp->dev, "failed to validate fw, ret %d", ret);
		return NULL;
	}

	memset(reg_vals, 0, sizeof(reg_vals));
	reg_vals[0] = PSP_START;
	reg_vals[1] = PSP_START_COPY_FW;
	ret = psp_exec(psp, reg_vals);
	if (ret) {
		dev_err(psp->dev, "failed to start fw, ret %d", ret);
		return NULL;
	}

	return psp;
}
