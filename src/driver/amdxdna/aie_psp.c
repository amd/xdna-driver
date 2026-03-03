// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <linux/device.h>
#include <linux/iopoll.h>
#include <linux/slab.h>

#include "aie_common.h"
#include "amdxdna_xen.h"

struct psp_device *aiem_psp_create(struct device *dev, struct psp_config *conf)
{
	struct psp_device *psp;
	u64 offset;

	psp = devm_kzalloc(dev, sizeof(*psp), GFP_KERNEL);
	if (!psp)
		return NULL;

	psp->dev = dev;
	memcpy(psp->psp_regs, conf->psp_regs, sizeof(psp->psp_regs));

	/* NPU firmware */
	psp->fw_buf_sz = ALIGN(conf->fw_size, PSP_FW_ALIGN);
	if (is_xen_initial_pvh_domain()) {
		psp->fw_buffer = amdxdna_xen_alloc_buf_phys(psp->dev,
							    psp->fw_buf_sz + PSP_FW_ALIGN,
							    &psp->fw_dma_handle);
		if (!psp->fw_buffer)
			return NULL;
		psp->fw_paddr = psp->fw_dma_handle;
	} else {
		psp->fw_buffer = devm_kmalloc(psp->dev,
					      psp->fw_buf_sz + PSP_FW_ALIGN,
					      GFP_KERNEL);
		if (!psp->fw_buffer)
			return NULL;

		psp->fw_paddr = virt_to_phys(psp->fw_buffer);
	}

	offset = ALIGN(psp->fw_paddr, PSP_FW_ALIGN) - psp->fw_paddr;
	psp->fw_paddr += offset;
	memcpy(psp->fw_buffer + offset, conf->fw_buf, conf->fw_size);

	if (!conf->certfw_size) {
		dev_dbg(dev, "no cert fw");
		goto done;
	}

	/* CERT firmware */
	psp->certfw_buf_sz = ALIGN(conf->certfw_size, PSP_CFW_ALIGN);
	psp->certfw_buffer = devm_kmalloc(dev,
					  psp->certfw_buf_sz + PSP_CFW_ALIGN,
					  GFP_KERNEL);
	if (!psp->certfw_buffer) {
		dev_err(dev, "no memory for cert fw buffer");
		return NULL;
	}

	psp->certfw_paddr = virt_to_phys(psp->certfw_buffer);
	offset = ALIGN(psp->certfw_paddr, PSP_CFW_ALIGN) - psp->certfw_paddr;
	psp->certfw_paddr += offset;
	memcpy(psp->certfw_buffer + offset, conf->certfw_buf, conf->certfw_size);
done:
	return psp;
}

