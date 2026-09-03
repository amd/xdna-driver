// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_cache.h>
#include <drm/drm_print.h>
#include <linux/errno.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "aie.h"
#include "amdxdna_coredump.h"
#include "amdxdna_ctx.h"
#include "amdxdna_drv.h"

static const size_t coredump_data_chunk_size = SZ_1M;

struct amdxdna_coredump_walk_arg {
	struct amdxdna_hwctx_key	key;

	struct aie_device		*aie;
	struct amdxdna_drm_get_array	*args;
	u8 __user			*buf;
	size_t				buf_size;
};

/* amdxdna_hwctx_match() casts the walk arg to struct amdxdna_hwctx_key. */
static_assert(offsetof(struct amdxdna_coredump_walk_arg, key) == 0,
	      "key must be the first member for amdxdna_hwctx_match()");

static size_t amdxdna_coredump_total_buf_size(struct aie_device *aie, struct amdxdna_hwctx *hwctx)
{
	u32 orig_col = hwctx->num_col - hwctx->num_unused_col;
	u32 num_bufs = aie->metadata.rows * orig_col;

	return num_bufs * coredump_data_chunk_size;
}

char *amdxdna_get_hwctx_coredump(struct aie_device *aie, struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_msg_buf_hdl **data_hdls = NULL;
	struct amdxdna_msg_buf_hdl *list_hdl = NULL;
	struct amdxdna_coredump_buf_entry *buf_list;
	size_t total_size;
	size_t offset;
	u32 num_bufs;
	int ret = 0;
	char *buf;
	int i;

	if (!aie->msg_ops.get_coredump)
		return ERR_PTR(-EOPNOTSUPP);

	total_size = amdxdna_coredump_total_buf_size(aie, hwctx);
	buf = kvmalloc(total_size, GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	num_bufs = total_size / coredump_data_chunk_size;
	list_hdl = amdxdna_alloc_msg_buff(xdna, num_bufs * sizeof(*buf_list));
	if (IS_ERR(list_hdl)) {
		ret = PTR_ERR(list_hdl);
		list_hdl = NULL;
		XDNA_ERR(xdna, "Failed to allocate buffer list: %d", ret);
		goto out;
	}

	buf_list = to_cpu_addr(list_hdl, 0);
	memset(buf_list, 0, to_buf_size(list_hdl));

	data_hdls = kzalloc_objs(*data_hdls, num_bufs);
	if (!data_hdls) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < num_bufs; i++) {
		data_hdls[i] = amdxdna_alloc_msg_buff(xdna, coredump_data_chunk_size);
		if (IS_ERR(data_hdls[i])) {
			ret = PTR_ERR(data_hdls[i]);
			data_hdls[i] = NULL;
			XDNA_ERR(xdna, "Failed to allocate data buffer %d: %d", i, ret);
			goto out;
		}

		memset(to_cpu_addr(data_hdls[i], 0), 0, to_buf_size(data_hdls[i]));
		drm_clflush_virt_range(to_cpu_addr(data_hdls[i], 0), to_buf_size(data_hdls[i]));

		buf_list[i].buf_addr = to_dma_addr(data_hdls[i], 0);
		buf_list[i].buf_size = coredump_data_chunk_size;
	}

	drm_clflush_virt_range(buf_list, to_buf_size(list_hdl));

	ret = aie->msg_ops.get_coredump(hwctx, list_hdl, num_bufs);
	if (ret) {
		XDNA_ERR(xdna, "Failed to get coredump from firmware: %d", ret);
		goto out;
	}

	for (i = 0, offset = 0; i < num_bufs; i++, offset += coredump_data_chunk_size)
		memcpy(buf + offset, to_cpu_addr(data_hdls[i], 0), coredump_data_chunk_size);

out:
	if (data_hdls) {
		for (i = 0; i < num_bufs; i++)
			amdxdna_free_msg_buff(data_hdls[i]);
	}
	kfree(data_hdls);
	amdxdna_free_msg_buff(list_hdl);
	if (!ret)
		return buf;

	kvfree(buf);
	return ERR_PTR(ret);
}

static int amdxdna_get_coredump_cb(struct amdxdna_hwctx *hwctx, void *arg)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_coredump_walk_arg *wa = arg;
	size_t total_size;
	char *buf;
	int ret;

	if (!amdxdna_client_visible(hwctx->client)) {
		XDNA_ERR(xdna, "Permission denied for context %u", wa->key.ctx_id);
		return -EPERM;
	}

	total_size = amdxdna_coredump_total_buf_size(wa->aie, hwctx);
	if (wa->buf_size < total_size) {
		XDNA_DBG(xdna, "Insufficient buffer size %zu, need %zu",
			 wa->buf_size, total_size);
		wa->args->element_size = total_size;
		return -ENOSPC;
	}

	if (hwctx->coredump) {
		buf = hwctx->coredump;
		hwctx->coredump = NULL;
	} else {
		buf = amdxdna_get_hwctx_coredump(wa->aie, hwctx);
	}
	if (IS_ERR(buf))
		return PTR_ERR(buf);
	ret = copy_to_user(wa->buf, buf, total_size);
	kvfree(buf);
	if (ret)
		return -EFAULT;

	return 0;
}

int amdxdna_get_coredump(struct aie_device *aie,
			 struct amdxdna_client *client,
			 struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_aie_coredump config = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_coredump_walk_arg wa;
	struct amdxdna_client *tmp_client;
	int ret = -ENOENT;
	size_t buf_size;
	u8 __user *buf;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!aie->msg_ops.get_coredump)
		return -EOPNOTSUPP;

	if (args->num_element != 1) {
		XDNA_ERR(xdna, "Invalid num_element %u, expected 1",
			 args->num_element);
		return -EINVAL;
	}

	buf_size = (size_t)args->num_element * args->element_size;
	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, buf_size)) {
		XDNA_ERR(xdna, "Failed to access buffer, element num %d size 0x%x",
			 args->num_element, args->element_size);
		return -EFAULT;
	}

	if (buf_size < sizeof(config)) {
		XDNA_ERR(xdna, "Insufficient buffer size: 0x%zx", buf_size);
		args->element_size = sizeof(config);
		return -ENOSPC;
	}

	if (copy_from_user(&config, buf, sizeof(config))) {
		XDNA_ERR(xdna, "Failed to copy coredump config from user");
		return -EFAULT;
	}

	if (XDNA_MBZ_DBG(xdna, &config.pad, sizeof(config.pad)))
		return -EINVAL;

	XDNA_DBG(xdna, "AIE Coredump request for context_id=%u pid=%llu",
		 config.context_id, config.pid);

	wa.key.ctx_id = config.context_id;
	wa.key.pid = config.pid;
	wa.buf_size = buf_size;
	wa.args = args;
	wa.aie = aie;
	wa.buf = buf;

	amdxdna_for_each_client(xdna, tmp_client) {
		ret = amdxdna_hwctx_walk(tmp_client, &wa,
					 amdxdna_hwctx_match,
					 amdxdna_get_coredump_cb);
		if (ret != -ENOENT)
			break;
	}
	if (ret == -ENOENT)
		XDNA_ERR(xdna, "Context %u for pid %llu not found",
			 config.context_id, config.pid);
	return ret;
}

static int amdxdna_free_saved_coredump_cb(struct amdxdna_hwctx *hwctx, void *arg)
{
	kvfree(hwctx->coredump);
	hwctx->coredump = NULL;
	return 0;
}

static bool amdxdna_saved_coredump_filter(struct amdxdna_hwctx *hwctx, void *arg)
{
	return !!hwctx->coredump;
}

int
amdxdna_set_auto_coredump_mode(struct amdxdna_client *client,
			       struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_attribute_state state = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_client *tmp_client;
	u32 buf_sz;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	buf_sz = min(args->buffer_size, sizeof(state));
	if (copy_from_user(&state, u64_to_user_ptr(args->buffer), buf_sz))
		return -EFAULT;

	if (state.state > 1)
		return -EINVAL;

	if (XDNA_MBZ_DBG(client->xdna, state.pad, sizeof(state.pad)))
		return -EINVAL;

	XDNA_DBG(xdna, "Setting auto coredump to %d", state.state);

	xdna->auto_coredump = state.state;

	/* auto core dump is disabled, clean up all saved cores. */
	if (!state.state) {
		amdxdna_for_each_client(xdna, tmp_client) {
			amdxdna_hwctx_walk(tmp_client, NULL, amdxdna_saved_coredump_filter,
					   amdxdna_free_saved_coredump_cb);
		}
	}

	return 0;
}

int
amdxdna_get_auto_coredump_mode(struct amdxdna_client *client,
			       struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_attribute_state state = {};
	struct amdxdna_dev *xdna = client->xdna;
	u32 buf_sz;

	state.state = xdna->auto_coredump;
	buf_sz = min(args->buffer_size, sizeof(state));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &state, buf_sz))
		return -EFAULT;

	return 0;
}
