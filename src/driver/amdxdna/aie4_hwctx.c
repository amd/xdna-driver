// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */
#include <linux/pm_runtime.h>
#include <drm/drm_cache.h>

#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "amdxdna_pm.h"

#include "aie4_pci.h"
#include "aie4_message.h"
#include "aie4_solver.h"
#include "aie4_msg_priv.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

static int aie4_alloc_resource(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct alloc_requests *xrs_req;
	int ret;

	xrs_req = kzalloc(sizeof(*xrs_req), GFP_KERNEL);
	if (!xrs_req)
		return -ENOMEM;

	xrs_req->cdo.start_cols = ctx->col_list;
	xrs_req->cdo.cols_len = ctx->col_list_len;
	xrs_req->cdo.ncols = ctx->num_col;
	xrs_req->cdo.qos_cap.opc = ctx->max_opc;

	xrs_req->rqos.gops = ctx->qos.gops;
	xrs_req->rqos.fps = ctx->qos.fps;
	xrs_req->rqos.dma_bw = ctx->qos.dma_bandwidth;
	xrs_req->rqos.latency = ctx->qos.latency;
	xrs_req->rqos.exec_time = ctx->qos.frame_exec_time;
	xrs_req->rqos.priority = ctx->qos.priority;

	xrs_req->rid = (uintptr_t)ctx;

	ret = aie4_xrs_allocate_resource(xdna->dev_handle->xrs_hdl, xrs_req, ctx);
	if (ret)
		XDNA_ERR(xdna, "Allocate AIE resource failed, ret %d", ret);

	kfree(xrs_req);
	return ret;
}

static void aie4_release_resource(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	int ret;

	ret = aie4_xrs_release_resource(xdna->dev_handle->xrs_hdl, (uintptr_t)ctx);
	if (ret)
		XDNA_ERR(xdna, "Release AIE resource failed, ret %d", ret);
}

static void aie4_ctx_col_list_fini(struct amdxdna_ctx *ctx)
{
	kfree(ctx->col_list);
}

static int aie4_ctx_col_list_init(struct amdxdna_ctx *ctx)
{
	u32 entries = 1;

	ctx->col_list = kmalloc_array(entries, sizeof(*ctx->col_list), GFP_KERNEL);
	if (!ctx->col_list)
		return -ENOMEM;

	ctx->col_list_len = entries;
	ctx->col_list[0] = 0;
	return 0;
}

int aie4_ctx_init(struct amdxdna_ctx *ctx)
{
	struct amdxdna_client *client = ctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_ctx_priv *priv = NULL;
	int ret;

	ret = pm_runtime_resume_and_get(xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "Resume failed, ret %d", ret);
		return ret;
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		ret = -ENOMEM;
		goto suspend;
	}
	ctx->priv = priv;

	priv->umq_bo = amdxdna_gem_get_obj(client, ctx->umq_bo, AMDXDNA_BO_SHARE);
	if (!priv->umq_bo) {
		XDNA_ERR(xdna, "cannot find umq_bo handle %d", ctx->umq_bo);
		ret = -ENOENT;
		goto free_priv;
	}

	/* col_list must be provided to the resolver */
	ret = aie4_ctx_col_list_init(ctx);
	if (ret) {
		XDNA_ERR(xdna, "Create col list failed, ret %d", ret);
		goto put_bo;
	}

	/* resolver to call load->aie4_create_context */
	ret = aie4_alloc_resource(ctx);
	if (ret) {
		XDNA_ERR(xdna, "Alloc hw resource failed, ret %d", ret);
		goto free_col_list;
	}

	XDNA_DBG(xdna, "ctx %s init completed", ctx->name);

	return 0;

free_col_list:
	aie4_ctx_col_list_fini(ctx);

put_bo:
	if (priv->umq_bo)
		drm_gem_object_put(to_gobj(priv->umq_bo));

free_priv:
	kfree(ctx->priv);
suspend:
	pm_runtime_mark_last_busy(xdna->ddev.dev);
	pm_runtime_put_autosuspend(xdna->ddev.dev);
	return ret;
}

void aie4_ctx_fini(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx_priv *priv = ctx->priv;

	xdna = ctx->client->xdna;

	/* only access hardware if device is active */
	if (!amdxdna_pm_resume_get(xdna)) {
		/* resolver to call unload->aie4_destroy_context */
		aie4_release_resource(ctx);
		amdxdna_pm_suspend_put(xdna);
	}

	/* free col_list */
	aie4_ctx_col_list_fini(ctx);
	if (priv->umq_bo)
		drm_gem_object_put(to_gobj(priv->umq_bo));

	kfree(ctx->priv);
	pm_runtime_mark_last_busy(xdna->ddev.dev);
	pm_runtime_put_autosuspend(xdna->ddev.dev);
}

void aie4_ctx_suspend(struct amdxdna_ctx *ctx, bool wait)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = ctx->client->xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie4_lock));

	aie4_destroy_context(ndev, ctx, 1);

	ctx->priv->status = CTX_STATE_DISCONNECTED;
}

int aie4_ctx_resume(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = ctx->client->xdna->dev_handle;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie4_lock));

	if (!ctx->priv) {
		XDNA_DBG(xdna, "skip uninitialized ctx");
		return 0;
	}

	/* recreate existing ctx */
	ret = aie4_create_context(xdna->dev_handle, ctx);
	if (!ret)
		ctx->priv->status = CTX_STATE_CONNECTED;
	else
		XDNA_WARN(xdna, "Failed to resume %s status 0x%x ret %d",
			  ctx->name, ctx->priv->status, ret);
	return ret;
}

#define HSA_QUEUE_READ_INDEX_OFFSET 0
#define check_read_index \
({ \
	u64 *read_index = (u64 *)((char *)amdxdna_gem_vmap(nctx->umq_bo) +	\
		HSA_QUEUE_READ_INDEX_OFFSET);					\
	XDNA_DBG(xdna, "read_idx %lld > seq %lld", *read_index, seq);		\
	((*read_index) > seq);							\
})

int aie4_cmd_wait(struct amdxdna_ctx *ctx, u64 seq, u32 timeout)
{
	struct amdxdna_ctx_priv *nctx = ctx->priv;
	struct col_entry *col_entry = nctx->col_entry;
	struct amdxdna_dev *xdna = ctx->client->xdna;
	unsigned long wait_jifs = MAX_SCHEDULE_TIMEOUT;
	long ret = 0;

	if (timeout)
		wait_jifs = msecs_to_jiffies(timeout);

	ret = wait_event_interruptible_timeout(col_entry->col_event,
					       ((col_entry && col_entry->needs_reset) ||
					       check_read_index),
					       wait_jifs);

	if (col_entry && col_entry->needs_reset)
		ret = -EAGAIN;

	return ret <= 0 ? ret : 0;
}

static int aie4_ctx_config_debug_bo(struct amdxdna_ctx *ctx, u32 bo_hdl, int attach)
{
	DECLARE_AIE4_MSG(aie4_msg_configure_hw_context, AIE4_MSG_OP_CONFIGURE_HW_CONTEXT);
	struct amdxdna_client *client = ctx->client;
	struct amdxdna_ctx_priv *nctx = ctx->priv;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_gem_obj *meta_bo;
	struct amdxdna_gem_obj *log_bo;
	struct fw_buffer_metadata *meta_buffer;
	u32 config_property;
	u32 prev_size;
	int ret;

	meta_bo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_SHARE);
	if (!meta_bo) {
		XDNA_ERR(xdna, "Get meta_bo %d failed", bo_hdl);
		ret = -EINVAL;
		goto err_out;
	}

	nctx->meta_bo_hdl = attach ? bo_hdl : AMDXDNA_INVALID_BO_HANDLE;

	meta_buffer = (struct fw_buffer_metadata *)amdxdna_gem_vmap(meta_bo);

	switch (meta_buffer->buf_type) {
	case AMDXDNA_FW_BUF_LOG:
		/*
		 * TODO: remove the workaround, cert_log are now enabled from xrt.ini
		 * apply workaround here before xrt-smi can enable single file for cert_log
		 * so that kernel doesn't need to touch the kva anymore.
		 */
		config_property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_LOG_BUFFER;
		log_bo = amdxdna_gem_get_obj(client, meta_buffer->bo_handle, AMDXDNA_BO_SHARE);
		break;
	case AMDXDNA_FW_BUF_DEBUG:
		config_property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_DEBUG_BUFFER;
		log_bo = amdxdna_gem_get_obj(client, meta_buffer->bo_handle, AMDXDNA_BO_SHARE);
		break;
	case AMDXDNA_FW_BUF_TRACE:
		config_property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_TRACE_BUFFER;
		log_bo = amdxdna_gem_get_obj(client, meta_buffer->bo_handle, AMDXDNA_BO_SHARE);
		break;
	case AMDXDNA_FW_BUF_DBG_Q:
		config_property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_DEBUG_QUEUE;
		log_bo = amdxdna_gem_get_obj(client, meta_buffer->bo_handle, AMDXDNA_BO_SHARE);
		break;
	default:
		XDNA_ERR(xdna, "unsupported buffer type %d bo %lld",
			 meta_buffer->buf_type, meta_buffer->bo_handle);
		ret = -EOPNOTSUPP;
		goto put_meta_bo;
	}

	if (!log_bo) {
		XDNA_ERR(xdna, "Get log_bo %lld failed", meta_buffer->bo_handle);
		ret = -EINVAL;
		goto put_meta_bo;
	}
	XDNA_DBG(xdna, "Found bo %lld", meta_buffer->bo_handle);

	/* assign dev_addr + offse to firmware */
	prev_size = 0;
	for (int i = 0; i < meta_buffer->num_ucs; i++) {
		struct uc_info_entry *entry = &meta_buffer->uc_info[i];
		u32 index = entry->index;
		u64 off_addr;

		if (index >= MAX_NUM_CERTS) {
			XDNA_ERR(xdna, "got invalid index %d, stop", index);
			ret = -EINVAL;
			goto put_log_bo;
		}

		if (!attach) {
			XDNA_INFO(xdna, "clear index %d logging", index);
			req.cert_logging.info[index].paddr = 0;
			req.cert_logging.info[index].size = 0;
			continue;
		}

		off_addr = (u64)((char *)amdxdna_gem_dev_addr(log_bo) + prev_size);

		/* skip any empty entry */
		if (entry->size == 0)
			continue;
		prev_size += entry->size;

		req.cert_logging.info[index].paddr = off_addr;
		req.cert_logging.info[index].size = entry->size;

		XDNA_DBG(xdna, "request cert index %d, paddr 0x%llx, size %d",
			 index, off_addr, entry->size);
	}

	req.cert_logging.num = attach ? meta_buffer->num_ucs : 0;

	req.hw_context_id = ctx->priv->hw_ctx_id;
	req.property = config_property;

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);

	XDNA_DBG(xdna, "Attach debug BO %d to %s, ret: %d", bo_hdl, ctx->name, ret);

put_log_bo:
	amdxdna_gem_put_obj(log_bo);
put_meta_bo:
	amdxdna_gem_put_obj(meta_bo);
err_out:
	return ret;
}

static int aie4_ctx_attach_debug_bo(struct amdxdna_ctx *ctx, u32 bo_hdl)
{
	return aie4_ctx_config_debug_bo(ctx, bo_hdl, 1);
}

static int aie4_ctx_detach_debug_bo(struct amdxdna_ctx *ctx, u32 bo_hdl)
{
	return aie4_ctx_config_debug_bo(ctx, bo_hdl, 0);
}

int aie4_parse_priority(u32 priority)
{
	switch (priority) {
	case AIE4_CONTEXT_PRIORITY_BAND_IDLE:
		return AMDXDNA_QOS_LOW_PRIORITY;
	case AIE4_CONTEXT_PRIORITY_BAND_NORMAL:
		return AMDXDNA_QOS_NORMAL_PRIORITY;
	case AIE4_CONTEXT_PRIORITY_BAND_FOCUS:
		return AMDXDNA_QOS_HIGH_PRIORITY;
	case AIE4_CONTEXT_PRIORITY_BAND_REAL_TIME:
		return AMDXDNA_QOS_REALTIME_PRIORITY;
	default:
		return 0;
	}
}

int aie4_ctx_config(struct amdxdna_ctx *ctx, u32 type, u64 value, void *buf, u32 size)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;

	switch (type) {
	case DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF:
		return aie4_ctx_attach_debug_bo(ctx, (u32)value);
	case DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF:
		return aie4_ctx_detach_debug_bo(ctx, (u32)value);
	default:
		XDNA_DBG(xdna, "Not supported type %d", type);
		return -EOPNOTSUPP;
	}
}
