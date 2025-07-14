/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _VE2_MGMT_H_
#define _VE2_MGMT_H_

#include <linux/xlnx-ai-engine.h>

struct amdxdna_dev;
struct amdxdna_ctx;

#define VE2_COL_SHIFT			25
#define VE2_ROW_SHIFT			20
#define VE2_ADDR(col, row, off) \
	(((col) << VE2_COL_SHIFT) + ((row) << VE2_ROW_SHIFT) + (off))

#define VE2_HANDSHAKE_OFF		0x88000
#define CERT_HANDSHAKE_OFF(col)		VE2_ADDR(col, 0, VE2_HANDSHAKE_OFF)

#define VE2_CERT_WAKEUP_OFF		0xC0000
#define VE2_EVENT_GENERATE_REG		0x00034008
#define VE2_USER_EVENT_ID		0xB6
#define VE2_SHIM_DATA_MEMORY_OFF	0xD0000
#define VE2_PROG_DATA_MEMORY_OFF	0x80000
#define VE2_MEM_TILE_MEMORY_OFF		0x0
#define VE2_CORE_TILE_MEMORY_OFF	0x0
#define HSA_QUEUE_READ_INDEX_OFFSET	0x0
#define HSA_QUEUE_WRITE_INDEX_OFFSET	0x10

#define SHIM_DATA_MEMORY_OFF(col, row, off) \
	VE2_ADDR(col, row, VE2_SHIM_DATA_MEMORY_OFF + (off))

#define SHIM_PROG_MEMORY_OFF(col, row, off) \
	VE2_ADDR(col, row, VE2_PROG_DATA_MEMORY_OFF + (off))

#define MEM_TILE_MEMORY_OFF(col, row, off) \
	VE2_ADDR(col, row, VE2_MEM_TILE_MEMORY_OFF + (off))

#define CORE_TILE_MEMORY_OFF(col, row, off) \
	VE2_ADDR(col, row, VE2_CORE_TILE_MEMORY_OFF + (off))

int ve2_mgmt_create_partition(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx);
int ve2_mgmt_destroy_partition(struct amdxdna_ctx *hwctx);
struct amdxdna_ctx *ve2_get_hwctx(struct amdxdna_dev *xdna, u32 col);
int notify_fw_cmd_ready(struct amdxdna_ctx *hwctx);

#endif /* _VE2_MGMT_H_ */
