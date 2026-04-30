/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 Layer 2: AIE HAL, firmware, and `ve2_hw_ops`.  `ve2_aux.h` includes this
 * for shared `struct amdxdna_dev_hdl` members (fw version / slots).
 */

#ifndef _VE2_HW_H_
#define _VE2_HW_H_

#include <linux/types.h>

struct amdxdna_hwctx;
struct amdxdna_dev;
struct amdxdna_dev_hdl;
struct amdxdna_sched_job;

/* Certificate image layout (AIE program data memory) */
#define VE2_PROG_DATA_MEMORY_OFF	0x80000
#define VE2_CERT_VERSION_OFF		0x50
#define VE2_CERT_VERSION_SIZE		0x40
#define VE2_FW_HASH_STRING_LENGTH	41
#define VE2_FW_DATE_STRING_LENGTH	11

struct ve2_firmware_version {
	u8 major;
	u8 minor;
	char git_hash[VE2_FW_HASH_STRING_LENGTH];
	char date[VE2_FW_DATE_STRING_LENGTH];
	u8 hotfix;
	u8 build;
};

struct ve2_firmware_status {
	u32 state;
	u32 abs_page_index;
	u32 ppc;
	u32 idle_status;
	u32 misc_status;
};

/*
 * struct ve2_hw_ops — single boundary from Layer 1 to Layer 2
 *
 * Layer 1: ve2_aux.c, ve2_ctx.c, ve2_debug.c, ve2_res_solver.c — use
 * ve2_hw_get_ops() only, not xlnx-aie / partition APIs directly.
 *
 * Layer 2: ve2_hw.c — implement ops and device firmware (former ve2_mgmt/ve2_fw).
 */
struct ve2_hw_ops {
	int (*ctx_init)(struct amdxdna_hwctx *hwctx, u32 start_col, u32 num_cols);
	void (*ctx_fini)(struct amdxdna_hwctx *hwctx);
	int (*cmd_submit)(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
			  u64 *seq);
	int (*cmd_wait)(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout_ms);
};

const struct ve2_hw_ops *ve2_hw_get_ops(void);

/* Device probe: request cert image, AIE partition init, broadcast, version read. */
int ve2_hw_load_cert_firmware(struct amdxdna_dev_hdl *xdna_hdl);

/* Per-column `struct ve2_firmware_status` pointers in @hdl (devm). */
int ve2_hw_init_fw_status_slots(struct amdxdna_dev *xdna, struct amdxdna_dev_hdl *hdl);

#endif /* _VE2_HW_H_ */
