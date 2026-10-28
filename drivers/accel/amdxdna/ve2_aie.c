// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2-private adapter for the Linux Xilinx AIE partition API. This is the
 * only VE2 translation unit that may include xlnx-ai-engine.h or call aie_*.
 *
 * Probe uses a whole-device partition to load CERT and read its version. A
 * hardware context uses its own column-range partition: the handshake is
 * written at initialization, the lead uC is woken, a user event is the
 * doorbell, and user_event1 is the completion callback.
 */

#include <linux/err.h>
#include <linux/slab.h>
#include <linux/xlnx-ai-engine.h>

#include "ve2_aie.h"

int ve2_aie_get_device_info(struct ve2_aie_device_info *info)
{
	struct aie_device_info aie_info;
	int ret;

	if (!info)
		return -EINVAL;

	ret = aie_get_device_info(&aie_info);
	if (ret)
		return ret;

	info->cols = aie_info.cols;
	info->rows = aie_info.rows;
	info->core_rows = aie_info.core_rows;
	info->mem_rows = aie_info.mem_rows;
	info->shim_rows = aie_info.shim_rows;
	return 0;
}

/* A zero @num_col requests the whole device, which is what probe uses. */
struct device *ve2_aie_partition_request(u32 start_col, u32 num_col,
					 ve2_aie_event_cb_fn event_cb,
					 void *event_priv, u32 *partition_id)
{
	struct aie_partition_req req = { };
	struct device *aie_dev;

	if (num_col)
		req.partition_id = aie_calc_part_id(start_col, num_col);
	req.user_event1_complete = event_cb;
	req.user_event1_priv = event_priv;

	aie_dev = aie_partition_request(&req);
	if (!IS_ERR(aie_dev) && partition_id)
		*partition_id = req.partition_id;

	return aie_dev;
}

void ve2_aie_partition_release(struct device *aie_dev)
{
	aie_partition_release(aie_dev);
}

int ve2_aie_partition_teardown(struct device *aie_dev)
{
	return aie_partition_teardown(aie_dev);
}

int ve2_aie_partition_initialize(struct device *aie_dev, enum ve2_aie_init_mode mode,
				 const struct ve2_aie_handshake *handshake,
				 u32 handshake_cols)
{
	struct aie_partition_init_args args = { };
	struct aie_op_handshake_data *hs = NULL;
	u32 col;
	int ret;

	switch (mode) {
	case VE2_AIE_INIT_FIRMWARE:
		args.init_opts = (AIE_PART_INIT_OPT_DEFAULT |
				  AIE_PART_INIT_OPT_DIS_TLAST_ERROR) &
				 ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;
		break;
	case VE2_AIE_INIT_RUNTIME:
		if (!handshake || !handshake_cols)
			return -EINVAL;
		args.init_opts = (AIE_PART_INIT_OPT_DEFAULT |
				  AIE_PART_INIT_OPT_HANDSHAKE |
				  AIE_PART_INIT_OPT_DIS_TLAST_ERROR) &
				 ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;
		break;
	default:
		return -EINVAL;
	}

	if (handshake_cols) {
		hs = kcalloc(handshake_cols, sizeof(*hs), GFP_KERNEL);
		if (!hs)
			return -ENOMEM;

		/*
		 * A zero dma_addr has the AIE driver stage each image in its own
		 * DMA buffer and free it once copied, so @handshake can be
		 * ordinary kernel memory that the caller frees on return.
		 */
		for (col = 0; col < handshake_cols; col++) {
			hs[col].addr = handshake[col].addr;
			hs[col].size = handshake[col].size;
			hs[col].loc.col = handshake[col].col;
			hs[col].loc.row = 0;
		}
		args.handshake = hs;
		args.handshake_cols = handshake_cols;
	}

	ret = aie_partition_initialize(aie_dev, &args);
	kfree(hs);
	return ret;
}

int ve2_aie_partition_wake_lead_uc(struct device *aie_dev)
{
	struct aie_location lead = { .col = 0, .row = 0 };

	return aie_partition_uc_wakeup(aie_dev, &lead);
}

int ve2_aie_load_cert(struct device *aie_dev, void *data)
{
	return aie_load_cert_broadcast(aie_dev, data);
}

int ve2_aie_read(struct device *aie_dev, u32 col, u32 row, size_t offset,
		 size_t size, void *buf)
{
	struct aie_location loc = { .col = col, .row = row };

	return aie_partition_read(aie_dev, loc, offset, size, buf);
}

int ve2_aie_write(struct device *aie_dev, u32 col, u32 row, size_t offset,
		  size_t size, void *buf)
{
	struct aie_location loc = { .col = col, .row = row };

	return aie_partition_write(aie_dev, loc, offset, size, buf, 0);
}
