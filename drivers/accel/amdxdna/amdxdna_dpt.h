/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */
#ifndef _AMDXDNA_DPT_H_
#define _AMDXDNA_DPT_H_

#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "aie.h"

/*
 * Firmware Debug/Profile/Trace (DPT) framework.
 *
 * A single struct amdxdna_dpt and one set of amdxdna_dpt_* helpers serve
 * firmware logging (xdna->fw_log). The handle's lifetime is guarded by
 * xdna->dpt_srcu so that disabling logging while N watchers are sleeping
 * inside amdxdna_dpt_get_data delivers -ESHUTDOWN to every one of them
 * and tears down the handle without UAF.
 */

#define AMDXDNA_DPT_FOOTER_SIZE		SZ_4K
#define AMDXDNA_DPT_POLL_INTERVAL_MS	10
#define AMDXDNA_DPT_FW_LOG_SIZE		SZ_4M

/* Common firmware log level scale used by user space (ioctl).
 * AIE2 and AIE4 firmwares both follow this numeric mapping internally.
 */
#define AMDXDNA_DPT_FW_LOG_LEVEL_NONE		0
#define AMDXDNA_DPT_FW_LOG_LEVEL_ERR		1
#define AMDXDNA_DPT_FW_LOG_LEVEL_WARN		2
#define AMDXDNA_DPT_FW_LOG_LEVEL_INFO		3
#define AMDXDNA_DPT_FW_LOG_LEVEL_DEBUG		4
#define AMDXDNA_DPT_FW_LOG_LEVEL_MAX		5  /* exclusive upper bound */

#define AMDXDNA_DPT_FW_LOG_LEVEL_DEFAULT	AMDXDNA_DPT_FW_LOG_LEVEL_WARN

enum amdxdna_dpt_status {
	AMDXDNA_DPT_INACTIVE,		/* kzalloc default */
	AMDXDNA_DPT_ACTIVE,		/* logging is on; watchers may sleep */
	AMDXDNA_DPT_SUSPENDING,		/* suspend in progress; admitted readers
					 * may drain the final batch, new readers
					 * and new timer arms blocked
					 */
	AMDXDNA_DPT_SUSPENDED,		/* paused by PM suspend; buffer preserved */
	AMDXDNA_DPT_SHUTTING_DOWN,	/* fini in progress; between status write and kfree */
};

enum amdxdna_dpt_kind {
	AMDXDNA_DPT_FW_LOG,
	AMDXDNA_DPT_KIND_MAX,
};

const char *amdxdna_dpt_kind_str(enum amdxdna_dpt_kind kind);
extern const char * const amdxdna_dpt_irq_name[AMDXDNA_DPT_KIND_MAX];

#define XDNA_DPT_PRINTK(level, dpt, fmt, args...) do {				\
	const struct amdxdna_dpt *__d = (dpt);					\
	XDNA_##level(__d->xdna, "%s: " fmt,					\
		     amdxdna_dpt_kind_str(__d->kind), ##args);			\
} while (0)

#define XDNA_DPT_ERR(dpt,  fmt, args...) XDNA_DPT_PRINTK(ERR,  dpt, fmt, ##args)
#define XDNA_DPT_WARN(dpt, fmt, args...) XDNA_DPT_PRINTK(WARN, dpt, fmt, ##args)
#define XDNA_DPT_INFO(dpt, fmt, args...) XDNA_DPT_PRINTK(INFO, dpt, fmt, ##args)
#define XDNA_DPT_DBG(dpt,  fmt, args...) XDNA_DPT_PRINTK(DBG,  dpt, fmt, ##args)

#define XDNA_DPT_MBZ_DBG(dpt, ptr, sz)	XDNA_MBZ_DBG((dpt)->xdna, ptr, sz)

/*
 * Layout matches the firmware ABI exactly so the on-the-wire format stays
 * compatible with what shim/xrt-smi already expects.
 */
struct amdxdna_dpt_footer {
	u8	minor;
	u8	major;
	u8	type;
	u8	reserved1;
	u32	payload_version;
	u8	reserved2[56];
	u32	tail;
} __packed;

struct amdxdna_dpt {
	struct amdxdna_dev		*xdna;
	struct aie_device		*aie;
	enum amdxdna_dpt_kind		 kind;
	enum amdxdna_dpt_status		 status;
	/*
	 * Kind-specific configuration: log level for FW_LOG,
	 * category bitmask for FW_TRACE.
	 */
	u32				 config;

	/* FW-reported metadata (filled once by amdxdna_dpt_read_metadata) */
	u8				 major;
	u8				 minor;
	u32				 payload_version;

	/* DMA ring buffer (FW writes, host reads) */
	struct amdxdna_msg_buf_hdl	*buf;
	u64				 tail;		/* kernel cache of FW write pointer */

	/* MSI / IRQ wiring (irq == 0 means request_irq failed) */
	void __iomem			*io_base;
	int				 irq;
	u32				 msi_idx;
	u32				 msi_address;

	/* deferred work + on-demand polling timer */
	struct work_struct		 work;
	struct timer_list		 timer;
	struct mutex			 timer_lock;	/* timer_refs / timer_delete_sync */
	refcount_t			 timer_refs;

	/* xrt-smi watchers park here */
	struct wait_queue_head		 wait;
};

/*
 * Top-level DPT lifecycle. Entry points called from per-generation
 * init/fini/suspend/resume after aie->msg_ops has been populated.
 * amdxdna_dpt_init auto-starts FW_LOG only; FW_TRACE remains inactive
 * at probe and is opt-in via the DRM_AMDXDNA_SET_FW_TRACE_STATE ioctl
 * to avoid generating large trace payloads unconditionally.
 */
int amdxdna_dpt_init(struct aie_device *aie);
int amdxdna_dpt_fini(struct aie_device *aie);
int amdxdna_dpt_suspend(struct aie_device *aie);
int amdxdna_dpt_resume(struct aie_device *aie);

int amdxdna_get_fw_log(struct aie_device *aie,
		       struct amdxdna_drm_get_array *args);
int amdxdna_get_fw_log_configs(struct aie_device *aie,
			       struct amdxdna_drm_get_array *args);
int amdxdna_set_fw_log_state(struct aie_device *aie,
			     struct amdxdna_drm_set_state *args);

#endif /* _AMDXDNA_DPT_H_ */
