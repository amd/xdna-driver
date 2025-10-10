// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024-2025, Advanced Micro Devices, Inc.
 */

#include "amdxdna_ctx.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_trace.h"
#include "aie2_pci.h"

#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

extern const struct drm_sched_backend_ops sched_ops;

static int aie2_load_hwctx(struct amdxdna_ctx *ctx)
{
	enum xdna_mailbox_channel_type type;
	struct xdna_mailbox_chann_info info;
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;
	void *mbox_chann;
	int ret;

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

static int aie2_unload_hwctx(struct amdxdna_ctx *ctx)
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
	ctx->priv->mbox_chann = NULL;
	return ret;
}

int aie2_hwctx_start(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;
#if KERNEL_VERSION(6, 15, 0) <= LINUX_VERSION_CODE
	const struct drm_sched_init_args args = {
		.ops = &sched_ops,
		.num_rqs = DRM_SCHED_PRIORITY_COUNT,
		.credit_limit = CTX_MAX_CMDS,
		.timeout = MAX_SCHEDULE_TIMEOUT,
		.name = ctx->name,
		.dev = xdna->ddev.dev,
	};
#endif

	struct drm_gpu_scheduler *sched;
	struct amdxdna_gem_obj *heap;
	struct amdxdna_dev_hdl *ndev;
	int ret;

	ndev = xdna->dev_handle;
	sched = &ctx->priv->sched;
	heap = ctx->priv->heap;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&ndev->aie2_lock));
#if KERNEL_VERSION(6, 15, 0) <= LINUX_VERSION_CODE
	ret = drm_sched_init(sched, &args);
#else
	ret = drm_sched_init(sched, &sched_ops, NULL, DRM_SCHED_PRIORITY_COUNT,
			     CTX_MAX_CMDS, 0, MAX_SCHEDULE_TIMEOUT,
			     NULL, NULL, ctx->name, xdna->ddev.dev);
#endif
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

	ret = aie2_load_hwctx(ctx);
	if (ret) {
		XDNA_ERR(xdna, "Alloc hw resource failed, ret %d", ret);
		goto destroy_entity;
	}

#ifdef AMDXDNA_DEVEL
	if (iommu_mode == AMDXDNA_IOMMU_NO_PASID) {
		ret = aie2_map_host_buf(xdna->dev_handle, ctx->priv->id,
					heap->mem.dma_addr, heap->mem.size);
	} else {
		ret = aie2_map_host_buf(xdna->dev_handle, ctx->priv->id,
					amdxdna_gem_uva(heap), heap->mem.size);
	}
#else
	ret = aie2_map_host_buf(xdna->dev_handle, ctx->priv->id,
				amdxdna_gem_uva(heap), heap->mem.size);
#endif
	if (ret) {
		XDNA_ERR(xdna, "Map host buffer failed, ret %d", ret);
		goto unload_hwctx;
	}

	ndev->hwctx_cnt++;
	return 0;

unload_hwctx:
	aie2_unload_hwctx(ctx);
destroy_entity:
	drm_sched_entity_destroy(&ctx->priv->entity);
fini_sched:
	drm_sched_fini(&ctx->priv->sched);
	return ret;
}

void aie2_hwctx_stop(struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx->client->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_handle->aie2_lock));
	drm_sched_entity_destroy(&ctx->priv->entity);
	aie2_unload_hwctx(ctx);
	wait_event(ctx->priv->job_free_waitq,
		   (ctx->submitted == atomic64_read(&ctx->job_free_cnt)));
	drm_sched_fini(&ctx->priv->sched);
	xdna->dev_handle->hwctx_cnt--;
}
