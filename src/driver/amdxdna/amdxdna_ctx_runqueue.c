// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include "amdxdna_drm.h"
#include "amdxdna_ctx_runqueue.h"

static int amdxdna_rq_start(struct amdxdna_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;
	int ret = 0;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	if (FIELD_GET(CTX_STATE_CONNECTED, ctx->status))
		goto unlock_and_out; /* Connected */

	ret = xdna->dev_info->ops->ctx_connect(ctx);
	if (ret) {
		XDNA_ERR(xdna, "Cannot connect");
		goto unlock_and_out;
	}

	list_move_tail(&ctx->entry, &rq->conn_list);

unlock_and_out:
	mutex_unlock(&xdna->dev_lock);
	return ret;
}

static void amdxdna_rq_stop(struct amdxdna_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;

	xdna = ctx_rq_to_xdna_dev(rq);
	if (!FIELD_GET(CTX_STATE_CONNECTED, ctx->status))
		return;

	xdna->dev_info->ops->ctx_disconnect(ctx);
}

/*
 * amdxdna_rq_pause_all - Disconnect all context with hardware context
 *
 * This can be used in suspend/resume flow or whenever temporarily stop all
 * the connecting contexts is needed.
 */
void amdxdna_rq_pause_all(struct amdxdna_ctx_rq *rq)
{
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;

	xdna = ctx_rq_to_xdna_dev(rq);
	WARN_ON(rq->paused);

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	list_for_each_entry(ctx, &rq->conn_list, entry)
		xdna->dev_info->ops->ctx_disconnect(ctx);

	rq->paused = true;
}

/*
 * amdxdna_rq_pause_all - Disconnect all context with hardware context
 *
 * This shoudl be called after amdxdna_rq_pause_all() to rerun all paused context.
 */
void amdxdna_rq_run_all(struct amdxdna_ctx_rq *rq)
{
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;

	xdna = ctx_rq_to_xdna_dev(rq);
	WARN_ON(!rq->paused);

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	list_for_each_entry(ctx, &rq->conn_list, entry)
		xdna->dev_info->ops->ctx_connect(ctx);

	rq->paused = false;
}

int amdxdna_rq_wait_for_run(struct amdxdna_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	int ret;

	if (FIELD_GET(CTX_STATE_CONNECTED, ctx->status))
		return 0;

	// TODO:
	// 1. Move from disconn list to run queue
	// 2. Schedule which context to start
	ret = amdxdna_rq_start(rq, ctx);

	// TODO: Wait this ctx status change to connected
	return ret;
}

void amdxdna_rq_add(struct amdxdna_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;

	xdna = ctx_rq_to_xdna_dev(rq);
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	list_add_tail(&ctx->entry, &rq->disconn_list);

	XDNA_DBG(xdna, "ctx %s added status 0x%x", ctx->name, ctx->status);
}

void amdxdna_rq_del(struct amdxdna_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;

	xdna = ctx_rq_to_xdna_dev(rq);
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	amdxdna_rq_stop(rq, ctx);
	list_del(&ctx->entry);

	XDNA_DBG(xdna, "ctx %s deleted status 0x%x", ctx->name, ctx->status);
}

void amdxdna_rq_init(struct amdxdna_ctx_rq *rq)
{
	INIT_LIST_HEAD(&rq->conn_list);
	INIT_LIST_HEAD(&rq->disconn_list);
	rq->paused = false;
}

void amdxdna_rq_fini(struct amdxdna_ctx_rq *rq)
{
}
