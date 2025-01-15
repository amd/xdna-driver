// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#include "amdxdna_ctx.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_trace.h"
#include "aie2_solver.h"
#include "aie2_pci.h"

#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

extern const struct drm_sched_backend_ops sched_ops;

static int aie2_alloc_resource(struct amdxdna_ctx *ctx)
{
	struct alloc_requests *xrs_req;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = ctx->client->xdna;
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

	ret = xrs_allocate_resource(xdna->xrs_hdl, xrs_req, ctx);
	if (ret)
		XDNA_ERR(xdna, "Allocate AIE resource failed, ret %d", ret);

	kfree(xrs_req);
	return ret;
}

static void aie2_release_resource(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;
	int ret;

	xdna = ctx->client->xdna;
	ret = xrs_release_resource(xdna->xrs_hdl, (uintptr_t)ctx);
	if (ret)
		XDNA_ERR(xdna, "Release AIE resource failed, ret %d", ret);
}

int aie2_hwctx_start(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
	struct drm_gpu_scheduler *sched;
	struct amdxdna_gem_obj *heap;
	int ret;

	sched = &ctx->priv->sched;
	heap = ctx->priv->heap;

	ret = drm_sched_init(sched, &sched_ops, ctx->priv->submit_wq,
			     DRM_SCHED_PRIORITY_COUNT,
			     CTX_MAX_CMDS, 0, MAX_SCHEDULE_TIMEOUT,
			     NULL, NULL, ctx->name, xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init DRM scheduler. ret %d", ret);
		return ret;
	}

	ret = drm_sched_entity_init(&ctx->priv->entity, DRM_SCHED_PRIORITY_NORMAL,
				    &sched, 1, NULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to initial sched entiry. ret %d", ret);
		goto fini_sched;
	}

	ret = aie2_alloc_resource(ctx);
	if (ret) {
		XDNA_ERR(xdna, "Alloc hw resource failed, ret %d", ret);
		goto destroy_entity;
	}

#ifdef AMDXDNA_DEVEL
	if (iommu_mode == AMDXDNA_IOMMU_NO_PASID) {
		ret = aie2_map_host_buf(xdna->dev_handle, ctx->priv->id,
					heap->mem.dma_addr, heap->mem.size);
		goto skip;
	}
#endif
	ret = aie2_map_host_buf(xdna->dev_handle, ctx->priv->id,
				heap->mem.userptr, heap->mem.size);
#ifdef AMDXDNA_DEVEL
skip:
#endif
	if (ret) {
		XDNA_ERR(xdna, "Map host buffer failed, ret %d", ret);
		goto release_resource;
	}

	ctx->status |= FIELD_PREP(CTX_STATE_CONNECTED, 1);
	return 0;

release_resource:
	aie2_release_resource(ctx);
destroy_entity:
	drm_sched_entity_destroy(&ctx->priv->entity);
fini_sched:
	drm_sched_fini(&ctx->priv->sched);
	return ret;
}

void aie2_hwctx_stop(struct amdxdna_ctx *ctx)
{
	if (!FIELD_GET(CTX_STATE_CONNECTED, ctx->status)) {
		XDNA_DBG(ctx->client->xdna, "%s was stopped, skip", ctx->name);
		return;
	}

	drm_sched_entity_destroy(&ctx->priv->entity);
	aie2_release_resource(ctx);
	ctx->status &= ~CTX_STATE_CONNECTED;
}

void aie2_hwctx_free(struct amdxdna_ctx *ctx)
{
	drm_sched_fini(&ctx->priv->sched);
}

int aie2_xrs_load_hwctx(struct amdxdna_ctx *ctx, struct xrs_action_load *action)
{
	enum xdna_mailbox_channel_type type;
	struct xdna_mailbox_chann_info info;
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;
	void *mbox_chann;
	int ret;

	ctx->start_col = action->part.start_col;
	ctx->num_col = action->part.ncols;

	xdna = ctx->client->xdna;
	ndev = xdna->dev_handle;

	ret = aie2_create_context(ndev, ctx, &info);
	if (ret) {
		XDNA_ERR(xdna, "create context failed, ret %d", ret);
		return ret;
	}

	if (aie2_pm_is_turbo(ndev))
		type = MB_CHANNEL_USER_POLL;
	else
		type = MB_CHANNEL_USER_NORMAL;
	mbox_chann = xdna_mailbox_create_channel(ndev->mbox, &info, type);
	if (!mbox_chann) {
		XDNA_ERR(xdna, "not able to create channel");
		goto failed;
	}

	trace_amdxdna_debug_point(ctx->name, ret, "channel created");
	XDNA_DBG(xdna, "%s mailbox channel irq: %d, msix_id: %d",
		 ctx->name, ret, info.msix_id);

	ctx->priv->mbox_chann = mbox_chann;
	return 0;

failed:
	aie2_destroy_context(xdna->dev_handle, ctx);
	return ret;
}

int aie2_xrs_unload_hwctx(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;
	int ret;

	xdna = ctx->client->xdna;
	xdna_mailbox_stop_channel(ctx->priv->mbox_chann);
	ret = aie2_destroy_context(xdna->dev_handle, ctx);
	if (ret)
		XDNA_ERR(xdna, "destroy context failed, ret %d", ret);

	/*
	 * The DRM scheduler thread might still running.
	 * Call xdna_mailbox_free_channel() when ctx is destroyed.
	 */
	xdna_mailbox_destroy_channel(ctx->priv->mbox_chann);
	return ret;
}
