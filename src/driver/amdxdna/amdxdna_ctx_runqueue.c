// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include "amdxdna_drm.h"
#include "amdxdna_ctx_runqueue.h"

#define RQ_WORK_JIFF msecs_to_jiffies(1000)

static int amdxdna_rq_start(struct amdxdna_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;
	int ret = 0;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	if (FIELD_GET(CTX_STATE_READY, ctx->status))
		goto unlock_and_out; /* Connected */

	ret = xdna->dev_info->ops->ctx_connect(ctx);
	if (ret == -EAGAIN)
		rq->max_connected = rq->connected_cnt;
	if (ret)
		goto unlock_and_out;

	if (list_empty(&rq->conn_list))
		queue_delayed_work(rq->delay_wq, &rq->delay_work, RQ_WORK_JIFF);
	list_move_tail(&ctx->entry, &rq->conn_list);
	rq->connected_cnt++;
	XDNA_DBG(xdna, "ctx %s started and moved to connect list", ctx->name);

unlock_and_out:
	mutex_unlock(&xdna->dev_lock);
	return ret;
}

static void amdxdna_rq_stop(struct amdxdna_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;

	xdna = ctx_rq_to_xdna_dev(rq);
	if (!FIELD_GET(CTX_STATE_READY, ctx->status))
		return;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	xdna->dev_info->ops->ctx_disconnect(ctx);
	list_move_tail(&ctx->entry, &rq->disconn_list);
	rq->connected_cnt--;
	if (list_empty(&rq->conn_list))
		cancel_delayed_work(&rq->delay_work);
	XDNA_DBG(xdna, "ctx %s stopped and moved to disconnect list", ctx->name);
}

static void amdxdna_rq_work(struct work_struct *work)
{
	struct amdxdna_ctx_rq *rq;
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	struct amdxdna_ctx *tmp;

	rq = container_of(work, struct amdxdna_ctx_rq, delay_work.work);
	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	list_for_each_entry_safe(ctx, tmp, &rq->conn_list, entry) {
		u64 completed = ctx->completed;
		u64 submitted = ctx->submitted;

		if (submitted == completed)
			ctx->idle_cnt++;
		else
			ctx->idle_cnt = 0;

		if (ctx->idle_cnt < 5)
			continue;

		amdxdna_rq_stop(rq, ctx);
	}

	if (rq->max_connected && rq->max_connected == rq->connected_cnt)
		goto skip;

	list_for_each_entry_safe(ctx, tmp, &rq->disconn_list, entry) {
		ctx->status |= FIELD_PREP(CTX_STATE_CONNECTING, 1);
		XDNA_DBG(xdna, "Wakeup %s", ctx->name);
		wake_up(&ctx->connect_waitq);
	}
skip:
	mutex_unlock(&xdna->dev_lock);

	mod_delayed_work(rq->delay_wq, &rq->delay_work, RQ_WORK_JIFF);
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
	struct amdxdna_ctx *tmp;
	int ret;

	xdna = ctx_rq_to_xdna_dev(rq);
	WARN_ON(!rq->paused);

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	list_for_each_entry_safe(ctx, tmp, &rq->conn_list, entry) {
		ret = xdna->dev_info->ops->ctx_connect(ctx);
		if (!ret)
			continue;

		list_move_tail(&ctx->entry, &rq->disconn_list);
		rq->connected_cnt--;
	}

	rq->paused = false;
}

int amdxdna_rq_wait_for_run(struct amdxdna_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna = ctx_rq_to_xdna_dev(rq);
	int ret;

try_connect:
	if (FIELD_GET(CTX_STATE_READY, ctx->status))
		return 0;

	ret = amdxdna_rq_start(rq, ctx);
	if (!ret) {
		wake_up_all(&ctx->connect_waitq);
		return 0; /* started */
	}

	if (ret && ret != -EAGAIN) {
		XDNA_ERR(xdna, "Failed to start %s", ctx->name);
		return ret;
	}

	// TODO: -EAGAIN from device.
	// Move this context to run queue -> amdxdna_rq_enqueue();
	// Select next context to run -> amdxdna_rq_sched();
	// Note: amdxdna_rq_sched() might or might not select current ctx to run

	ret = wait_event_interruptible(ctx->connect_waitq,
				       FIELD_GET(CTX_STATE_CONNECTING, ctx->status) ||
				       FIELD_GET(CTX_STATE_READY, ctx->status));
	if (!ret)
		goto try_connect;

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

int amdxdna_rq_init(struct amdxdna_ctx_rq *rq)
{
	rq->delay_wq = alloc_ordered_workqueue("xdna_ctx_runqueue", 0);
	if (!rq->delay_wq)
		return -ENOMEM;

	INIT_LIST_HEAD(&rq->conn_list);
	INIT_LIST_HEAD(&rq->disconn_list);
	INIT_DELAYED_WORK(&rq->delay_work, amdxdna_rq_work);
	rq->paused = false;

	return 0;
}

void amdxdna_rq_fini(struct amdxdna_ctx_rq *rq)
{
	cancel_delayed_work_sync(&rq->delay_work);
	destroy_workqueue(rq->delay_wq);
}
