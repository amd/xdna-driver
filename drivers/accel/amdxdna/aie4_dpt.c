// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <linux/rcupdate.h>
#include <linux/string.h>

#include "aie.h"
#include "aie4.h"
#include "aie4_msg_priv.h"
#include "amdxdna_dpt.h"
#include "amdxdna_mailbox_helper.h"
#include "amdxdna_drv.h"

int aie4_fw_log_init(struct amdxdna_dev *xdna, size_t size, u32 level)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_dpt *dpt;
	u32 msi_idx = 0, msi_address = 0;
	int ret;

	if (level >= AIE4_FW_LOG_LEVEL_MAX) {
		XDNA_ERR(xdna, "Invalid firmware log level: %d", level);
		return -EINVAL;
	}

	dpt = rcu_dereference_protected(xdna->fw_log.data,
					lockdep_is_held(&xdna->dev_lock));
	if (!dpt) {
		XDNA_ERR(xdna, "FW log handle not allocated");
		return -ENXIO;
	}

	ret = aie4_start_fw_log(ndev, dpt->buf, level, size, &msi_idx, &msi_address);
	if (ret) {
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to start FW log: %d", ret);
		return ret;
	}

	dpt->io_base = ndev->mbox_base;
	dpt->msi_address = msi_address & AIE4_DPT_MSI_ADDR_MASK;
	dpt->msi_idx = msi_idx;

	return 0;
}

int aie4_fw_log_config(struct amdxdna_dev *xdna, u32 level)
{
	struct aie4_msg_runtime_config_fw_log_level cfg = { .log_level = level };

	if (level == AIE4_FW_LOG_LEVEL_OFF || level >= AIE4_FW_LOG_LEVEL_MAX) {
		XDNA_ERR(xdna, "Invalid firmware log level: %d", level);
		return -EINVAL;
	}

	return aie4_set_runtime_cfg(xdna->dev_handle, AIE4_RUNTIME_CONFIG_FW_LOG_LEVEL,
				    &cfg, sizeof(cfg));
}

int aie4_fw_log_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	DECLARE_AIE_MSG(aie4_msg_stop_fw_log, AIE4_MSG_OP_STOP_FW_LOG);
	int ret;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(xdna, "Failed to stop FW log: %d", ret);

	return ret;
}

/* Max bytes printed per dmesg line; firmware entries are newline-delimited
 * text, so split on '\n' and cap overly long lines at this chunk size.
 */
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

int aie4_fw_trace_init(struct amdxdna_dev *xdna, size_t size, u32 categories)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	u32 msi_idx = 0, msi_address = 0;
	struct amdxdna_dpt *dpt;
	int ret;

	dpt = rcu_dereference_protected(xdna->fw_trace.data,
					lockdep_is_held(&xdna->dev_lock));
	if (!dpt) {
		XDNA_ERR(xdna, "FW trace handle not allocated");
		return -ENXIO;
	}

	ret = aie4_start_fw_trace(ndev, dpt->buf, size, categories, &msi_idx,
				  &msi_address);
	if (ret) {
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to start FW trace: %d", ret);
		return ret;
	}

	dpt->io_base = ndev->mbox_base;
	dpt->msi_address = msi_address & AIE4_DPT_MSI_ADDR_MASK;
	dpt->msi_idx = msi_idx;

	return 0;
}

int aie4_fw_trace_config(struct amdxdna_dev *xdna, u32 categories)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	DECLARE_AIE_MSG(aie4_msg_set_fw_trace_categories,
			AIE4_MSG_OP_SET_FW_TRACE_CATEGORIES);
	int ret;

	req.categories = categories;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(xdna,
			 "Set FW trace categories failed, ret %d status 0x%x",
			 ret, resp.status);
	return ret;
}

int aie4_fw_trace_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	DECLARE_AIE_MSG(aie4_msg_stop_fw_trace, AIE4_MSG_OP_STOP_FW_TRACE);
	int ret;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(xdna, "Failed to stop FW trace: %d", ret);

	return ret;
}
