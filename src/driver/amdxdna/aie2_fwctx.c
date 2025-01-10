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

static int aie2_alloc_resource(struct amdxdna_hwctx *hwctx)
{
	struct alloc_requests *xrs_req;
	struct amdxdna_dev *xdna;
	int ret;

	xdna = hwctx->client->xdna;
	xrs_req = kzalloc(sizeof(*xrs_req), GFP_KERNEL);
	if (!xrs_req)
		return -ENOMEM;

	xrs_req->cdo.start_cols = hwctx->col_list;
	xrs_req->cdo.cols_len = hwctx->col_list_len;
	xrs_req->cdo.ncols = hwctx->num_col;
	xrs_req->cdo.qos_cap.opc = hwctx->max_opc;

	xrs_req->rqos.gops = hwctx->qos.gops;
	xrs_req->rqos.fps = hwctx->qos.fps;
	xrs_req->rqos.dma_bw = hwctx->qos.dma_bandwidth;
	xrs_req->rqos.latency = hwctx->qos.latency;
	xrs_req->rqos.exec_time = hwctx->qos.frame_exec_time;
	xrs_req->rqos.priority = hwctx->qos.priority;

	xrs_req->rid = (uintptr_t)hwctx;

	ret = xrs_allocate_resource(xdna->xrs_hdl, xrs_req, hwctx);
	if (ret)
		XDNA_ERR(xdna, "Allocate AIE resource failed, ret %d", ret);

	kfree(xrs_req);
	return ret;
}

static void aie2_release_resource(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna;
	int ret;

	xdna = hwctx->client->xdna;
	ret = xrs_release_resource(xdna->xrs_hdl, (uintptr_t)hwctx);
	if (ret)
		XDNA_ERR(xdna, "Release AIE resource failed, ret %d", ret);
}

int aie2_fwctx_start(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct drm_gpu_scheduler *sched;
	struct amdxdna_gem_obj *heap;
	int ret;

	sched = &hwctx->priv->sched;
	heap = hwctx->priv->heap;

	ret = drm_sched_init(sched, &sched_ops, hwctx->priv->submit_wq,
			     DRM_SCHED_PRIORITY_COUNT,
			     HWCTX_MAX_CMDS, 0, MAX_SCHEDULE_TIMEOUT,
			     NULL, NULL, hwctx->name, xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init DRM scheduler. ret %d", ret);
		return ret;
	}

	ret = drm_sched_entity_init(&hwctx->priv->entity, DRM_SCHED_PRIORITY_NORMAL,
				    &sched, 1, NULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to initial sched entiry. ret %d", ret);
		goto fini_sched;
	}

	ret = aie2_alloc_resource(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Alloc hw resource failed, ret %d", ret);
		goto destroy_entity;
	}

#ifdef AMDXDNA_DEVEL
	if (iommu_mode == AMDXDNA_IOMMU_NO_PASID) {
		ret = aie2_map_host_buf(xdna->dev_handle, hwctx->priv->id,
					heap->mem.dma_addr, heap->mem.size);
		goto skip;
	}
#endif
	ret = aie2_map_host_buf(xdna->dev_handle, hwctx->priv->id,
				heap->mem.userptr, heap->mem.size);
#ifdef AMDXDNA_DEVEL
skip:
#endif
	if (ret) {
		XDNA_ERR(xdna, "Map host buffer failed, ret %d", ret);
		goto release_resource;
	}

	hwctx->status |= FIELD_PREP(HWCTX_STATE_CONNECTED, 1);
	return 0;

release_resource:
	aie2_release_resource(hwctx);
destroy_entity:
	drm_sched_entity_destroy(&hwctx->priv->entity);
fini_sched:
	drm_sched_fini(&hwctx->priv->sched);
	return ret;
}

void aie2_fwctx_stop(struct amdxdna_hwctx *hwctx)
{
	if (!FIELD_GET(HWCTX_STATE_CONNECTED, hwctx->status)) {
		XDNA_DBG(hwctx->client->xdna, "%s was stopped, skip", hwctx->name);
		return;
	}

	aie2_release_resource(hwctx);
	hwctx->status &= ~HWCTX_STATE_CONNECTED;
}

void aie2_fwctx_free(struct amdxdna_hwctx *hwctx)
{
	drm_sched_entity_destroy(&hwctx->priv->entity);
	drm_sched_fini(&hwctx->priv->sched);
}

int aie2_xrs_load_fwctx(struct amdxdna_hwctx *hwctx, struct xrs_action_load *action)
{
	enum xdna_mailbox_channel_type type;
	struct xdna_mailbox_chann_info info;
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;
	void *mbox_chann;
	int ret;

	hwctx->start_col = action->part.start_col;
	hwctx->num_col = action->part.ncols;

	xdna = hwctx->client->xdna;
	ndev = xdna->dev_handle;

	ret = aie2_create_context(ndev, hwctx, &info);
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

	trace_amdxdna_debug_point(hwctx->name, ret, "channel created");
	XDNA_DBG(xdna, "%s mailbox channel irq: %d, msix_id: %d",
		 hwctx->name, ret, info.msix_id);

	hwctx->priv->mbox_chann = mbox_chann;
	return 0;

failed:
	aie2_destroy_context(xdna->dev_handle, hwctx);
	return ret;
}

int aie2_xrs_unload_fwctx(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna;
	int ret;

	xdna = hwctx->client->xdna;
	xdna_mailbox_stop_channel(hwctx->priv->mbox_chann);
	ret = aie2_destroy_context(xdna->dev_handle, hwctx);
	if (ret)
		XDNA_ERR(xdna, "destroy context failed, ret %d", ret);

	/*
	 * The DRM scheduler thread might still running.
	 * Call xdna_mailbox_free_channel() when hwctx is destroyed.
	 */
	xdna_mailbox_destroy_channel(hwctx->priv->mbox_chann);
	return ret;
}
