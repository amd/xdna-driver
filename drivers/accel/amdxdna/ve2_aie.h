/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2-private abstraction over the Xilinx AIE partition driver.
 */

#ifndef _VE2_AIE_H_
#define _VE2_AIE_H_

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/types.h>

struct ve2_aie_device_info {
	u16 cols;
	u16 rows;
	u16 core_rows;
	u16 mem_rows;
	u16 shim_rows;
};

struct ve2_aie_handshake {
	void		*addr;
	dma_addr_t	dma_addr;
	size_t		size;
	size_t		offset;
	u32		col;
	u32		row;
};

enum ve2_aie_init_mode {
	VE2_AIE_INIT_FIRMWARE,
	VE2_AIE_INIT_RUNTIME,
	VE2_AIE_INIT_RUNTIME_PERF,
};

enum ve2_aie_error_category {
	VE2_AIE_ERROR_SATURATION,
	VE2_AIE_ERROR_FP,
	VE2_AIE_ERROR_STREAM,
	VE2_AIE_ERROR_ACCESS,
	VE2_AIE_ERROR_BUS,
	VE2_AIE_ERROR_INSTRUCTION,
	VE2_AIE_ERROR_ECC,
	VE2_AIE_ERROR_LOCK,
	VE2_AIE_ERROR_DMA,
	VE2_AIE_ERROR_MEM_PARITY,
};

enum ve2_aie_error_module {
	VE2_AIE_ERROR_MODULE_MEMORY,
	VE2_AIE_ERROR_MODULE_CORE,
	VE2_AIE_ERROR_MODULE_PL,
};

struct ve2_aie_error {
	u32 category;
	u32 module;
	u32 error_id;
	u32 col;
	u32 row;
};

struct ve2_aie_errors {
	u32 num_err;
	struct ve2_aie_error errors[];
};

typedef void (*ve2_aie_event_cb_fn)(u32 partition_id, void *priv);
typedef void (*ve2_aie_error_cb_fn)(void *priv);

int ve2_aie_get_device_info(struct ve2_aie_device_info *info);
struct device *ve2_aie_partition_request(u32 start_col, u32 num_col,
					 ve2_aie_event_cb_fn event_cb,
					 void *event_priv, u32 *partition_id);
void ve2_aie_partition_release(struct device *aie_dev);
int ve2_aie_partition_teardown(struct device *aie_dev);
int ve2_aie_partition_initialize(struct device *aie_dev, enum ve2_aie_init_mode mode,
				 const struct ve2_aie_handshake *handshake,
				 u32 handshake_cols);
int ve2_aie_partition_handshake_update(struct device *aie_dev,
				       const struct ve2_aie_handshake *handshake,
				       u32 handshake_cols);
int ve2_aie_partition_wake_lead_uc(struct device *aie_dev);

int ve2_aie_load_cert(struct device *aie_dev, void *data);
int ve2_aie_read(struct device *aie_dev, u32 col, u32 row, size_t offset,
		 size_t size, void *buf);
int ve2_aie_write(struct device *aie_dev, u32 col, u32 row, size_t offset,
		  size_t size, void *buf);
int ve2_aie_priv_read(struct device *aie_dev, size_t offset, size_t size, void *buf);
int ve2_aie_priv_write(struct device *aie_dev, size_t offset, size_t size, void *buf);
int ve2_aie_coredump(struct device *aie_dev, size_t size, void *buf);

int ve2_aie_get_freq(struct device *aie_dev, u64 *freq);
int ve2_aie_set_freq(struct device *aie_dev, u64 freq);
int ve2_aie_get_fd(struct device *aie_dev);

int ve2_aie_register_error_cb(struct device *aie_dev, ve2_aie_error_cb_fn cb, void *priv);
int ve2_aie_unregister_error_cb(struct device *aie_dev);
struct ve2_aie_errors *ve2_aie_get_errors(struct device *aie_dev);
void ve2_aie_free_errors(struct ve2_aie_errors *errors);

#endif /* _VE2_AIE_H_ */
