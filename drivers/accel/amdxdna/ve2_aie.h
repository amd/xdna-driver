/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2-private abstraction over the Xilinx AIE partition driver.
 * Covers probe (device geometry, CERT load, version read) and the runtime
 * partition used by a hardware context (CERT handshake, uC wake-up, user
 * event doorbell and completion callback).
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

/* One column's CERT handshake image, copied into that column's uC memory. */
struct ve2_aie_handshake {
	void		*addr;
	size_t		size;
	u32		col;
};

enum ve2_aie_init_mode {
	VE2_AIE_INIT_FIRMWARE,
	VE2_AIE_INIT_RUNTIME,
};

typedef void (*ve2_aie_event_cb_fn)(u32 partition_id, void *priv);

int ve2_aie_get_device_info(struct ve2_aie_device_info *info);
struct device *ve2_aie_partition_request(u32 start_col, u32 num_col,
					 ve2_aie_event_cb_fn event_cb,
					 void *event_priv, u32 *partition_id);
void ve2_aie_partition_release(struct device *aie_dev);
int ve2_aie_partition_teardown(struct device *aie_dev);
int ve2_aie_partition_initialize(struct device *aie_dev, enum ve2_aie_init_mode mode,
				 const struct ve2_aie_handshake *handshake,
				 u32 handshake_cols);
int ve2_aie_partition_wake_lead_uc(struct device *aie_dev);
int ve2_aie_load_cert(struct device *aie_dev, void *data);
int ve2_aie_read(struct device *aie_dev, u32 col, u32 row, size_t offset,
		 size_t size, void *buf);
int ve2_aie_write(struct device *aie_dev, u32 col, u32 row, size_t offset,
		  size_t size, void *buf);

#endif /* _VE2_AIE_H_ */
