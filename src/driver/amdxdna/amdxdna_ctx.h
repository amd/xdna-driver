/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_CTX_H_
#define _AMDXDNA_CTX_H_

#include <linux/kref.h>
#include <linux/wait.h>
#include <drm/gpu_scheduler.h>
#include "drm_local/amdxdna_accel.h"
#include "xrs.h"

/*
 * Define the maximum number of pending commands in a hardware context.
 * Must be power of 2!
 */
#define HWCTX_MAX_CMDS		8
#define HWCTX_MAX_TIMEOUT	10000 /* miliseconds */

extern struct attribute_group hwctx_group;

struct amdxdna_hwctx {
	struct amdxdna_client		*client;
	u32				id;
	u32				xrs_id;
	u32				start_col;
	u32				num_col;
	u32				fw_ctx_id;
	struct aie_qos			qos;
	void				*mbox_chan;
	struct amdxdna_xclbin		*xclbin;
	struct amdxdna_gem_obj		*heap;
	bool				stopped;
	char				*name;

	struct drm_gpu_scheduler	sched;
	struct drm_sched_entity		entity;

	spinlock_t			io_lock; /* protect seq and cmd order */
	struct dma_fence		*pending[HWCTX_MAX_CMDS];
	u32				num_pending;
	u64				seq;
};

void amdxdna_hwctx_remove_all(struct amdxdna_client *client);
void amdxdna_stop_ctx_by_col_map(struct amdxdna_client *client, u32 col_map);
void amdxdna_restart_ctx(struct amdxdna_client *client);
void amdxdna_hwctx_suspend(struct amdxdna_client *client);
void amdxdna_hwctx_resume(struct amdxdna_client *client);

int amdxdna_hwctx_status(struct drm_device *dev, u32 *buf_size,
			 struct amdxdna_drm_query_hwctx __user *buf);

int amdxdna_drm_create_hwctx_legacy_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_create_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_destroy_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_exec_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_wait_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int amdxdna_drm_create_hwctx_unsec_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);

#endif /* _AMDXDNA_CTX_H_ */
