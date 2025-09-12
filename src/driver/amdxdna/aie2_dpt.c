// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include "aie2_pci.h"
#include "aie2_msg_priv.h"
#include "amdxdna_mgmt.h"

int aie2_fw_log_init(struct amdxdna_dev *xdna, size_t size, u8 level)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl = xdna->fw_log->dma_hdl;
	u32 msi_idx, msi_address;
	int ret;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_config_fw_log(xdna->dev_handle, dma_hdl, size, &msi_idx, &msi_address);
	if (ret) {
		/* Sliently fail for device generation that don't support FW logging */
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to init fw log buffer: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}

	ret = aie2_set_log_level(xdna->dev_handle, level);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log level: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}

	ret = aie2_set_log_format(xdna->dev_handle, FW_LOG_FORMAT_FULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log format: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}

	ret = aie2_set_log_destination(xdna->dev_handle, FW_LOG_DESTINATION_DRAM);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log destination: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);

	xdna->fw_log->io_base = xdna->dev_handle->mbox_base;
	xdna->fw_log->msi_address = msi_address & AIE2_DPT_MSI_ADDR_MASK;
	xdna->fw_log->msi_idx = msi_idx;

	return ret;
}

int aie2_fw_log_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl = xdna->fw_log->dma_hdl;
	int ret;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_set_log_destination(xdna->dev_handle, FW_LOG_DESTINATION_FIXED);
	if (ret) {
		/* Sliently fail for device generation that don't support FW logging */
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to reset fw log destination: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}

	ret = aie2_config_fw_log(xdna->dev_handle, dma_hdl, 0, NULL, NULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to reset fw log buffer: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);
	return 0;
}
