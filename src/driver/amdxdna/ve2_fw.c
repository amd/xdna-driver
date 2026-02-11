// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/version.h>

#include "amdxdna_of_drv.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_fw.h"

int ve2_store_firmware_version(struct ve2_firmware_version *c_version, struct device *xaie_dev)
{
	struct ve2_firmware_version *version;
	int ret = 0;

	version = kzalloc(sizeof(*version), GFP_KERNEL);
	if (!version)
		return -ENOMEM;

	ret = ve2_partition_read(xaie_dev, 0, 0, VE2_PROG_DATA_MEMORY_OFF + VE2_CERT_VERSION_OFF,
				 VE2_CERT_VERSION_SIZE, version);
	if (ret < 0) {
		pr_err("Failed to read firmware version, ret=%d\n", ret);
		kfree(version);
		return ret;
	}

	c_version->major = version->major;
	c_version->minor = version->minor;
	strscpy(c_version->git_hash, version->git_hash, VE2_FW_HASH_STRING_LENGTH);
	c_version->git_hash[VE2_FW_HASH_STRING_LENGTH - 1] = '\0';
	strscpy(c_version->date, version->date, VE2_FW_DATE_STRING_LENGTH);
	c_version->date[VE2_FW_DATE_STRING_LENGTH - 1] = '\0';
	kfree(version);

	pr_debug("Firmware version: %u.%u, hash=%s, date=%s\n",
		 c_version->major, c_version->minor, c_version->git_hash, c_version->date);

	return 0;
}

static int get_firmware_status(struct amdxdna_dev *xdna, struct device *aie_dev,
			       u32 lead_col, u32 col)
{
	struct ve2_firmware_status *cs = xdna->dev_handle->fw_slots[lead_col + col];
	struct handshake *hs = NULL;
	int ret = 0;

	hs = kzalloc(sizeof(*hs), GFP_KERNEL);
	if (!hs) {
		XDNA_ERR(xdna, "No memory for handshake.\n");
		return -ENOMEM;
	}

	ret = ve2_partition_read_privileged_mem(aie_dev, col,
						offsetof(struct handshake, mpaie_alive),
						sizeof(struct handshake), (void *)hs);
	if (ret < 0) {
		XDNA_ERR(xdna, "aie_partition_read failed with ret %d\n", ret);
		goto done;
	}

	cs->state = hs->vm.fw_state;
	cs->abs_page_index = hs->vm.abs_page_index;
	cs->ppc = hs->vm.ppc;
	cs->idle_status = hs->cert_idle_status;
	cs->misc_status = hs->misc_status;

	XDNA_INFO(xdna, "Firmware status of col = %u\n", col);
	XDNA_INFO(xdna, "FW state: %u\n", cs->state);
	XDNA_INFO(xdna, "abs_page_index: %u\n", cs->abs_page_index);
	XDNA_INFO(xdna, "ppc: %u\n", cs->ppc);
	XDNA_INFO(xdna, "FW idle_status: %u\n", cs->idle_status);
	XDNA_INFO(xdna, "misc_status: %u\n", cs->misc_status);

done:
	kfree(hs);
	return ret;
}

int ve2_get_firmware_status(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_ctx_priv *priv_ctx = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	int ret = 0;

	XDNA_DBG(xdna, "Getting firmware status: hwctx=%p, start_col=%u, num_col=%u",
		 hwctx, priv_ctx->start_col, priv_ctx->num_col);

	if (!priv_ctx->aie_dev) {
		XDNA_ERR(xdna, "Partition does not have aie device handle\n");
		return -ENODEV;
	}

	for (u32 col = 0; col < priv_ctx->num_col; col++) {
		ret = get_firmware_status(xdna, priv_ctx->aie_dev, priv_ctx->start_col, col);
		if (ret < 0)
			XDNA_ERR(xdna, "Failed to get cert status for col %d ret = %d\n", col, ret);
	}

	return ret;
}
