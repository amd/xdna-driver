// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_drv.h>
#include <drm/drm_print.h>
#include <linux/errno.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "aie.h"
#include "amdxdna_ctx.h"
#include "amdxdna_ctx_status.h"
#include "amdxdna_pci_drv.h"

struct amdxdna_hwctx_status_ctx {
	struct amdxdna_hwctx_key	key;

	struct aie_device		*aie;
	struct amdxdna_drm_get_array	*array_args;
};

/* amdxdna_hwctx_match() casts the walk arg to struct amdxdna_hwctx_key. */
static_assert(offsetof(struct amdxdna_hwctx_status_ctx, key) == 0,
	      "key must be the first member for amdxdna_hwctx_match()");

static int amdxdna_fill_hwctx_status_entry(struct aie_device *aie,
					   struct amdxdna_hwctx *hwctx,
					   struct amdxdna_drm_get_array *array_args)
{
	struct amdxdna_drm_hwctx_entry *tmp __free(kfree) = NULL;
	struct amdxdna_drm_hwctx_entry __user *buf;
	u32 size;

	/*
	 * Out of output slots. This is a benign "buffer full" condition (the
	 * caller reports the entries that fit), distinct from a real failure
	 * like -EFAULT below, so the walk caller can tell them apart.
	 */
	if (!array_args->num_element)
		return -ENOSPC;

	tmp = kzalloc_obj(*tmp);
	if (!tmp)
		return -ENOMEM;

	tmp->pid = hwctx->client->pid;
	strscpy(tmp->name, hwctx->client->name, sizeof(tmp->name));
	tmp->context_id = hwctx->id;
	tmp->hwctx_id = hwctx->fw_ctx_id;
	tmp->start_col = hwctx->start_col;
	tmp->num_col = hwctx->num_col;
	tmp->state = amdxdna_hwctx_report_state(hwctx, &tmp->command_submissions,
						&tmp->command_completions);
	tmp->pasid = hwctx->client->pasid;
	tmp->heap_usage = hwctx->client->heap_usage;
	tmp->priority = hwctx->qos.priority;
	tmp->gops = hwctx->qos.gops;
	tmp->fps = hwctx->qos.fps;
	tmp->dma_bandwidth = hwctx->qos.dma_bandwidth;
	tmp->latency = hwctx->qos.latency;
	tmp->frame_exec_time = hwctx->qos.frame_exec_time;

	/* Optional FW health is best-effort; ignore errors. */
	if (aie->msg_ops.fill_hwctx_health)
		aie->msg_ops.fill_hwctx_health(aie, hwctx, tmp);

	buf = u64_to_user_ptr(array_args->buffer);
	size = min(sizeof(*tmp), array_args->element_size);

	if (copy_to_user(buf, tmp, size))
		return -EFAULT;

	array_args->buffer += size;
	array_args->num_element--;

	return 0;
}

/*
 * Visibility-gated emitter shared by the HW_CONTEXTS / HW_CONTEXT_ALL /
 * HW_CONTEXT_BY_ID walks: a context the caller may not see (different Linux
 * user without CAP_SYS_ADMIN) is silently skipped so its existence is not
 * disclosed.
 */
static int amdxdna_hwctx_status_cb(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_hwctx_status_ctx *ctx = arg;

	if (!amdxdna_client_visible(hwctx->client))
		return 0;

	return amdxdna_fill_hwctx_status_entry(ctx->aie, hwctx, ctx->array_args);
}

int amdxdna_get_hwctx_status(struct aie_device *aie,
			     struct amdxdna_client *client,
			     struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_get_array array_args = {};
	struct amdxdna_hwctx_status_ctx ctx = { .aie = aie };
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_client *tmp_client;
	int ret = 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	array_args.element_size = sizeof(struct amdxdna_drm_query_hwctx);
	array_args.buffer = args->buffer;
	array_args.num_element = args->buffer_size / array_args.element_size;
	ctx.array_args = &array_args;
	amdxdna_for_each_client(xdna, tmp_client) {
		ret = amdxdna_hwctx_walk(tmp_client, &ctx, NULL,
					 amdxdna_hwctx_status_cb);
		if (ret)
			break;
	}

	/*
	 * -ENOSPC means the output buffer filled up; report the entries
	 * that fit. Any other error (e.g. -EFAULT from copy_to_user) is a real
	 * failure and must be propagated instead of a partial success.
	 */
	if (ret && ret != -ENOSPC)
		return ret;

	args->buffer_size -= (u32)(array_args.buffer - args->buffer);
	return 0;
}

int amdxdna_query_ctx_status_array(struct aie_device *aie,
				   struct amdxdna_client *client,
				   struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_get_array array_args = {};
	struct amdxdna_hwctx_status_ctx ctx = { .aie = aie };
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_client *tmp_client;
	int ret = 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!args->element_size || args->element_size > SZ_4K ||
	    args->num_element > SZ_1K) {
		XDNA_DBG(xdna, "Invalid element size %u or number of element %u",
			 args->element_size, args->num_element);
		return -EINVAL;
	}

	array_args.element_size = min(args->element_size,
				      sizeof(struct amdxdna_drm_hwctx_entry));
	array_args.buffer = args->buffer;
	array_args.num_element = args->num_element * args->element_size /
				 array_args.element_size;
	ctx.array_args = &array_args;
	amdxdna_for_each_client(xdna, tmp_client) {
		ret = amdxdna_hwctx_walk(tmp_client, &ctx, NULL,
					 amdxdna_hwctx_status_cb);
		if (ret)
			break;
	}

	/*
	 * -ENOSPC just means the output buffer filled up; report the entries
	 * that fit. Any other error (e.g. -EFAULT from copy_to_user) is a real
	 * failure and must be propagated instead of a partial success.
	 */
	if (ret && ret != -ENOSPC)
		return ret;

	args->element_size = array_args.element_size;
	args->num_element = (u32)((array_args.buffer - args->buffer) /
				  args->element_size);

	return 0;
}

int amdxdna_query_ctx_status_by_id(struct aie_device *aie,
				   struct amdxdna_client *client,
				   struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_hwctx_entry input = {};
	struct amdxdna_drm_get_array array_args = {};
	struct amdxdna_hwctx_status_ctx ctx = { .aie = aie };
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_client *tmp_client;
	int ret = -ENOENT;
	size_t min_input_sz;
	size_t buf_size;
	size_t min_sz;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (args->num_element != 1) {
		XDNA_ERR(xdna, "Invalid num_element %u, expected 1",
			 args->num_element);
		return -EINVAL;
	}

	if (args->element_size > SZ_4K) {
		XDNA_DBG(xdna, "Invalid element size %u", args->element_size);
		return -EINVAL;
	}

	/*
	 * BY_ID is an input query: the caller must supply at least @context_id
	 * and @pid so the target context can be looked up. Reject an
	 * element_size too small to cover them (including 0), otherwise the
	 * missing bytes would read back as zero and fail later with a
	 * misleading "Invalid context ID or PID".
	 */
	min_input_sz = offsetofend(struct amdxdna_drm_hwctx_entry, pid);
	if (args->element_size < min_input_sz) {
		XDNA_ERR(xdna, "Invalid element size %u, need at least %zu",
			 args->element_size, min_input_sz);
		return -EINVAL;
	}

	/*
	 * Negotiate the element size against the caller's struct the same way
	 * the HW_CONTEXT_ALL walk does, so user space built against an older
	 * (smaller) amdxdna_drm_hwctx_entry still works after the struct grows.
	 * Only the negotiated number of bytes are read from and written back to
	 * the user buffer; @input is zero-initialized so any field the caller
	 * did not provide reads as zero.
	 */
	min_sz = min_t(size_t, args->element_size, sizeof(input));
	buf_size = (size_t)args->num_element * args->element_size;
	if (buf_size < min_sz) {
		XDNA_ERR(xdna, "Insufficient buffer size: 0x%zx", buf_size);
		return -EINVAL;
	}

	if (copy_from_user(&input, u64_to_user_ptr(args->buffer), min_sz)) {
		XDNA_ERR(xdna, "Failed to copy hwctx entry from user");
		return -EFAULT;
	}

	if (!input.context_id || !input.pid) {
		XDNA_ERR(xdna, "Invalid context ID %u or PID %lld",
			 input.context_id, input.pid);
		return -EINVAL;
	}

	array_args.element_size = min_t(size_t, args->element_size,
					sizeof(struct amdxdna_drm_hwctx_entry));
	array_args.buffer = args->buffer;
	array_args.num_element = 1;

	ctx.array_args = &array_args;
	ctx.key.ctx_id = input.context_id;
	ctx.key.pid = input.pid;

	amdxdna_for_each_client(xdna, tmp_client) {
		ret = amdxdna_hwctx_walk(tmp_client, &ctx,
					 amdxdna_hwctx_match,
					 amdxdna_hwctx_status_cb);
		if (ret != -ENOENT)
			break;
	}

	/*
	 * A matched context that the caller may not see is skipped by the gated
	 * emitter (nothing emitted, num_element stays 1). Do not disclose its
	 * existence: report it as not found, same as a genuinely missing context.
	 */
	if (!ret && array_args.num_element)
		ret = -ENOENT;

	if (ret == -ENOENT)
		XDNA_DBG(xdna, "Context %u for pid %lld not found",
			 input.context_id, input.pid);
	if (ret)
		return ret;

	args->element_size = array_args.element_size;
	args->num_element = 1;

	return 0;
}
