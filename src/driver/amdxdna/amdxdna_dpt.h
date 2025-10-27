/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_DPT_H_
#define _AMDXDNA_DPT_H_

#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

#include "amdxdna_mgmt.h"

#define AMDXDNA_DPT_FOOTER_SIZE		SZ_4K
#define AMDXDNA_DPT_POLL_INTERVAL_MS	10

#define AMDXDNA_DPT_FW_LOG_NAME		"xdna_fw_log"
#define AMDXDNA_DPT_FW_LOG_MSG_ALIGN	8

#define AMDXDNA_DPT_FW_TRACE_NAME	"xdna_fw_trace"

struct amdxdna_dpt_footer {
	u8				minor;
	u8				major;
	u8				type;
	u8				reserved1;
	u32				payload_version;
	u8				reserved2[56];
	u32				tail;
} __packed;

struct amdxdna_dpt {
	bool				enabled;
	u8				minor;
	u8				major;
	u32				payload_version;
	char				name[20];
	struct amdxdna_dev		*xdna;
	struct amdxdna_mgmt_dma_hdl	*dma_hdl;
	struct wait_queue_head		wait;
	bool				polling;
	struct work_struct		work;
	struct timer_list		timer;
	void			__iomem *io_base;
	int				irq;
	u32				msi_idx;
	u32				msi_address;
	u64				tail;

	/* Below members are required only until dumping to dmesg is supported */
	bool				dump_to_dmesg;
	u64				head;
	u8				*local_buffer;
	u32				size;
	void (*parse)(struct amdxdna_dev *xdna, char *buffer, size_t size);
};

int amdxdna_dpt_init(struct amdxdna_dev *xdna);
int amdxdna_dpt_fini(struct amdxdna_dev *xdna);

int amdxdna_dpt_resume(struct amdxdna_dev *xdna);
int amdxdna_dpt_suspend(struct amdxdna_dev *xdna);

int amdxdna_dpt_dump_to_dmesg(struct amdxdna_dpt *dpt, bool enable);

int amdxdna_set_fw_log_state(struct amdxdna_dev *xdna, struct amdxdna_drm_set_state *args);

int amdxdna_get_fw_log(struct amdxdna_dev *xdna, struct amdxdna_drm_get_array *args);
int amdxdna_get_fw_trace(struct amdxdna_dev *xdna, struct amdxdna_drm_get_array *args);

#endif /* _AMDXDNA_DPT_H_ */
