// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include "aie4_pci.h"
#include "aie4_msg_priv.h"
#include "amdxdna_mgmt.h"

/* Stay well below printk record limits and allow room for prefixes */
#define AIE4_FW_LOG_CHUNK	800

void aie4_fw_log_parse(struct amdxdna_dev *xdna, char *buffer, size_t size)
{
	size_t offset = 0;

	if (!buffer || size == 0)
		return;

	while (offset < size) {
		const char *p = buffer + offset;
		size_t remaining = size - offset;
		size_t n = remaining < AIE4_FW_LOG_CHUNK ? remaining : AIE4_FW_LOG_CHUNK;
		const char *nl = memchr(p, '\n', n);

		if (nl)
			n = (size_t)(nl - p) + 1;

		XDNA_INFO(xdna, "[FW LOG] %.*s", (int)n, p);
		offset += n;
	}
}

int aie4_fw_log_init(struct amdxdna_dev *xdna, size_t size, u8 level)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl = xdna->fw_log->dma_hdl;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	u32 msi_idx, msi_address;
	int ret;

	if (is_npu3_vf_dev(pdev)) {
		XDNA_DBG(xdna, "not supported on npu3 vf device");
		return -EOPNOTSUPP;
	}

	mutex_lock(&xdna->dev_handle->aie4_lock);
	ret = aie4_start_fw_log(xdna->dev_handle, dma_hdl, level, size, &msi_idx, &msi_address);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log buffer: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie4_lock);
		return -EOPNOTSUPP;
	}
	mutex_unlock(&xdna->dev_handle->aie4_lock);

	xdna->fw_log->io_base = xdna->dev_handle->mbox_base;
	xdna->fw_log->msi_address = msi_address & AIE4_DPT_MSI_ADDR_MASK;
	xdna->fw_log->msi_idx = msi_idx;

	return ret;
}

int aie4_fw_log_config(struct amdxdna_dev *xdna, u8 level)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	if (is_npu3_vf_dev(pdev)) {
		XDNA_DBG(xdna, "not supported on npu3 vf device");
		return -EOPNOTSUPP;
	}

	if (level == AIE4_DYNAMIC_LOG_NONE || level > AIE4_DYNAMIC_LOG_DBG) {
		XDNA_ERR(xdna,  "Invalid firmware log level: %d", level);
		return -EINVAL;
	}

	mutex_lock(&xdna->dev_handle->aie4_lock);
	ret = aie4_set_log_level(xdna->dev_handle, level);
	if (ret)
		XDNA_ERR(xdna, "Failed to init fw log level: %d", ret);
	mutex_unlock(&xdna->dev_handle->aie4_lock);

	return ret;
}

int aie4_fw_log_fini(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	if (is_npu3_vf_dev(pdev)) {
		XDNA_DBG(xdna, "not supported on npu3 vf device");
		return -EOPNOTSUPP;
	}

	mutex_lock(&xdna->dev_handle->aie4_lock);
	ret = aie4_stop_fw_log(xdna->dev_handle);
	if (ret) {
		XDNA_ERR(xdna, "Failed to reset fw log buffer: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie4_lock);
		return ret;
	}
	mutex_unlock(&xdna->dev_handle->aie4_lock);
	return 0;
}
