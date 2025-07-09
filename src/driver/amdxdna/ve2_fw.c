// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/version.h>

#include "amdxdna_of_drv.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_fw.h"

int ve2_store_firmware_version(struct amdxdna_dev_hdl *xdna_hdl, struct device *xaie_dev)
{
	struct amdxdna_dev *xdna = xdna_hdl->xdna;
	struct ve2_firmware_version *version;
	struct aie_location loc;
	int ret;

	version = kzalloc(sizeof(*version), GFP_KERNEL);
	if (!version)
		return -ENOMEM;

	loc.col = 0;
	loc.row = 0;
	ret = aie_partition_read(xaie_dev, loc, VE2_PROG_DATA_MEMORY_OFF + VE2_CERT_VERSION_OFF,
				 VE2_CERT_VERSION_SIZE, version);
	if (ret < 0) {
		XDNA_ERR(xdna, "aie_partition_read failed with ret %d\n", ret);
		kfree(version);
		return ret;
	}

	memcpy(&xdna_hdl->fw_version, version, sizeof(*version));
	XDNA_INFO(xdna, "CERT major: %u\n", xdna_hdl->fw_version.major);
	XDNA_INFO(xdna, "CERT minor: %u\n", xdna_hdl->fw_version.minor);
	XDNA_INFO(xdna, "CERT git hash: %s\n", xdna_hdl->fw_version.git_hash);
	XDNA_INFO(xdna, "CERT git hash date: %s\n", xdna_hdl->fw_version.date);
	kfree(version);

	return 0;
}

static int get_firmware_status(struct amdxdna_dev *xdna, struct device *aie_dev, u32 col)
{
	struct ve2_firmware_status *cs = xdna->dev_handle->fw_slots[col];
	struct aie_location loc;
	struct handshake *hs;
	int ret = 0;

	hs = kzalloc(sizeof(*hs), GFP_KERNEL);
	if (!hs) {
		XDNA_ERR(xdna, "No memory for handshake.\n");
		return -ENOMEM;
	}

	loc.col = col;
	loc.row = 0;

	ret = aie_partition_read(aie_dev, loc, 0, sizeof(*hs), hs);
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
	XDNA_INFO(xdna, "state: %u\n", cs->state);
	XDNA_INFO(xdna, "abs_page_index: %u\n", cs->abs_page_index);
	XDNA_INFO(xdna, "ppc: %u\n", cs->ppc);
	XDNA_INFO(xdna, "idle_status: %u\n", cs->idle_status);
	XDNA_INFO(xdna, "misc_status: %u\n", cs->misc_status);

done:
	kfree(hs);
	return ret;
}

int ve2_get_firmware_status(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_ctx_priv *priv_ctx = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 start_col = priv_ctx->start_col;
	u32 num_col = priv_ctx->num_col;
	u32 relative_col;
	int ret;

	if (!priv_ctx->aie_part) {
		XDNA_ERR(xdna, "Partition does not have aie device handle\n");
		return -ENODEV;
	}

	for (u32 col = start_col; col < start_col + num_col; col++) {
		relative_col = col - start_col;
		ret = get_firmware_status(xdna, priv_ctx->aie_part, relative_col);
		if (ret < 0) {
			XDNA_ERR(xdna, "Failed to get fw status for col %d ret %d\n", relative_col,
				 ret);
			break;
		}
	}

	return ret;
}
