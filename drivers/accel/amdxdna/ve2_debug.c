// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 debug / info ioctls: hwctx array for XRT aie_partition_info query.
 */

#include <drm/drm_device.h>
#include <drm/drm_drv.h>
#include <linux/cleanup.h>
#include <linux/errno.h>
#include <linux/minmax.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "drm/amdxdna_accel.h"
#include "amdxdna_gem.h"

#include "amdxdna_ctx.h"
#include "amdxdna_drv.h"
#include "ve2_debug.h"
#include "ve2_hwctx.h"
#include "ve2_hq.h"
#include "ve2_trace.h"

static int ve2_hwctx_status_cb(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_drm_hwctx_entry *tmp __free(kfree) = NULL;
	struct amdxdna_drm_get_array *array_args = arg;
	struct amdxdna_drm_hwctx_entry __user *buf;
	struct ve2_hwctx_priv *vp;
	u32 size;

	if (!array_args->num_element)
		return 0;

	tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	vp = ve2_hw_priv(hwctx);
	tmp->pid = hwctx->client->pid;
	tmp->context_id = hwctx->id;
	tmp->hwctx_id = hwctx->id;
	tmp->start_col = hwctx->start_col;
	tmp->num_col = hwctx->num_col ? hwctx->num_col : hwctx->num_tiles;
	tmp->migrations = 0;
	tmp->preemptions = 0;
	tmp->errors = 0;
	tmp->suspensions = 0;
	if (hwctx->priv) {
		tmp->command_submissions = hwctx->priv->seq;
		tmp->command_completions = hwctx->priv->completed;
	}
	if (vp) {
		tmp->command_submissions = vp->submitted;
		tmp->command_completions = vp->completed;
		tmp->state = vp->state;
	} else {
		tmp->state = AMDXDNA_HWCTX_STATE_ACTIVE;
	}
	tmp->pasid = hwctx->client->pasid;
	tmp->heap_usage = hwctx->client->heap_usage;
	tmp->priority = hwctx->qos.priority;
	tmp->gops = hwctx->qos.gops;
	tmp->fps = hwctx->qos.fps;
	tmp->dma_bandwidth = hwctx->qos.dma_bandwidth;
	tmp->latency = hwctx->qos.latency;
	tmp->frame_exec_time = hwctx->qos.frame_exec_time;

	VE2_TRACE(hwctx->client->xdna,
		  "hwctx_status: id=%u pid=%d start_col=%u num_col=%u (handle for XRT)",
		  tmp->context_id, (int)tmp->pid, tmp->start_col, tmp->num_col);

	buf = u64_to_user_ptr(array_args->buffer);
	size = min(sizeof(*tmp), array_args->element_size);
	if (copy_to_user(buf, tmp, size)) {
		VE2_TRACE(hwctx->client->xdna,
			  "hwctx_status: copy_to_user FAILED buf=%p size=%u elem_size=%zu",
			  buf, size, sizeof(*tmp));
		return -EFAULT;
	}

	array_args->buffer += size;
	array_args->num_element--;

	return 0;
}

static int ve2_query_ctx_status_array(struct amdxdna_client *client,
				      struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_get_array array_args;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_client *tmp_client;
	u32 req_elem_size = args->element_size;
	u32 req_num_element = args->num_element;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (args->element_size > SZ_4K || args->num_element > SZ_1K)
		return -EINVAL;

	array_args.element_size = min(args->element_size,
				      sizeof(struct amdxdna_drm_hwctx_entry));
	array_args.buffer = args->buffer;
	array_args.num_element = args->num_element * args->element_size /
				 array_args.element_size;

	list_for_each_entry(tmp_client, &xdna->client_list, node) {
		ret = amdxdna_hwctx_walk(tmp_client, &array_args, ve2_hwctx_status_cb);
		if (ret)
			break;
	}

	args->element_size = array_args.element_size;
	args->num_element = (u32)((array_args.buffer - args->buffer) /
				  args->element_size);

	VE2_TRACE(xdna, "query_ctx_status: req_size=%u req_num=%u out_size=%u num_ele=%u ret=%d",
		  req_elem_size, req_num_element, array_args.element_size, args->num_element, ret);

	return ret;
}

static int ve2_get_hwctx_mem_bitmap(struct amdxdna_client *client,
				    struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	struct ve2_hwctx_link *link;
	struct ve2_hwctx_priv *vp;
	u32 context_id = args->element_size;
	u32 mem_bitmap = 0;
	int idx;

	idx = srcu_read_lock(&client->hwctx_srcu);
	hwctx = xa_load(&client->hwctx_xa, context_id);
	if (!hwctx) {
		VE2_TRACE(xdna, "mem_bitmap: hwctx %u not found", context_id);
		srcu_read_unlock(&client->hwctx_srcu, idx);
		return -EINVAL;
	}

	vp = ve2_hw_priv(hwctx);
	if (vp) {
		mem_bitmap = vp->mem_bitmap;
	} else if (hwctx->aux_ctx_priv) {
		link = hwctx->aux_ctx_priv;
		mem_bitmap = link->mem_bitmap;
	}
	srcu_read_unlock(&client->hwctx_srcu, idx);

	VE2_TRACE(xdna, "mem_bitmap: ctx=%u bitmap=0x%x pid=%d",
		  context_id, mem_bitmap, client->pid);

	if (copy_to_user(u64_to_user_ptr(args->buffer), &mem_bitmap, sizeof(mem_bitmap)))
		return -EFAULT;

	args->num_element = 1;
	return 0;
}

int ve2_debug_get_aie_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	(void)client;
	(void)args;
	return -EOPNOTSUPP;
}

int ve2_debug_set_aie_state(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	(void)client;
	(void)args;
	return -EOPNOTSUPP;
}

int ve2_debug_get_array(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	VE2_TRACE(xdna, "GET_ARRAY pid=%d param=%u num_elet=%u ele_sz=%u buffer=0x%llx pad=0x%x",
		  client->pid, args->param, args->num_element, args->element_size,
		  args->buffer, args->pad);

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	/*
	 * dev_lock is already held by amdxdna_drm_get_array_ioctl().
	 * Do not lock again (non-recursive mutex -> deadlock).
	 */
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	switch (args->param) {
	case DRM_AMDXDNA_HW_CONTEXT_ALL:
		ret = ve2_query_ctx_status_array(client, args);
		break;
	case DRM_AMDXDNA_HWCTX_MEM_BITMAP:
		ret = ve2_get_hwctx_mem_bitmap(client, args);
		break;
	case DRM_AMDXDNA_BO_USAGE:
		ret = amdxdna_drm_get_bo_usage(&xdna->ddev, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported GET_ARRAY param %u", args->param);
		ret = -EOPNOTSUPP;
	}

	drm_dev_exit(idx);
	VE2_TRACE(xdna, "GET_ARRAY exit pid=%d param=%u ret=%d num_element=%u element_size=%u",
		  client->pid, args->param, ret, args->num_element, args->element_size);
	return ret;
}
