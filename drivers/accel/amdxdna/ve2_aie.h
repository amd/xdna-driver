/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2-private abstraction over the Xilinx AIE partition driver.
 * This slice covers probe: device geometry, CERT load, and version read.
 */

#ifndef _VE2_AIE_H_
#define _VE2_AIE_H_

#include <linux/device.h>
#include <linux/types.h>

struct ve2_aie_device_info {
	u16 cols;
	u16 rows;
	u16 core_rows;
	u16 mem_rows;
	u16 shim_rows;
};

enum ve2_aie_init_mode {
	VE2_AIE_INIT_FIRMWARE,
};

int ve2_aie_get_device_info(struct ve2_aie_device_info *info);
struct device *ve2_aie_partition_request(void);
void ve2_aie_partition_release(struct device *aie_dev);
int ve2_aie_partition_teardown(struct device *aie_dev);
int ve2_aie_partition_initialize(struct device *aie_dev, enum ve2_aie_init_mode mode);
int ve2_aie_load_cert(struct device *aie_dev, void *data);
int ve2_aie_read(struct device *aie_dev, u32 col, u32 row, size_t offset,
		 size_t size, void *buf);

#endif /* _VE2_AIE_H_ */
