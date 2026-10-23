// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2-private adapter for the Linux Xilinx AIE partition API. This is the
 * only VE2 translation unit that may include xlnx-ai-engine.h or call aie_*.
 *
 * Probe uses a whole-device partition to load CERT and read its version.
 * Runtime handshake, register write, and completion are added with commands.
 */

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

struct device *ve2_aie_partition_request(void)
{
	struct aie_partition_req req = { };

	return aie_partition_request(&req);
}

void ve2_aie_partition_release(struct device *aie_dev)
{
	aie_partition_release(aie_dev);
}

int ve2_aie_partition_teardown(struct device *aie_dev)
{
	return aie_partition_teardown(aie_dev);
}

int ve2_aie_partition_initialize(struct device *aie_dev, enum ve2_aie_init_mode mode)
{
	struct aie_partition_init_args args = { };

	if (mode != VE2_AIE_INIT_FIRMWARE)
		return -EINVAL;

	args.init_opts = (AIE_PART_INIT_OPT_DEFAULT | AIE_PART_INIT_OPT_DIS_TLAST_ERROR) &
			 ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;
	return aie_partition_initialize(aie_dev, &args);
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
