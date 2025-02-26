// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include "amdxdna_drm.h"
#include "aie2_pci.h"

uint context_limit;
module_param(context_limit, uint, 0444);
MODULE_PARM_DESC(context_limit, "Maximum number of context, 0 = Use default");

uint hwctx_limit;
module_param(hwctx_limit, uint, 0444);
MODULE_PARM_DESC(hwctx_limit, "[Debug] Maximum number of hwctx. 0 = Use default");

#define RQ_CTX_IDLE_COUNT 3

static inline bool ctx_is_debug(struct amdxdna_ctx *ctx)
{
	return ctx->priv->status == CTX_STATE_DEBUG;
}

static inline bool ctx_is_fatal(struct amdxdna_ctx *ctx)
{
	if (ctx->priv->status == CTX_STATE_DEAD)
		return true;

	return ctx_is_debug(ctx);
}

static inline bool ctx_is_disconnected(struct amdxdna_ctx *ctx)
{
	return ctx->priv->status == CTX_STATE_DISCONNECTED;
}

static inline bool ctx_is_dispatched(struct amdxdna_ctx *ctx)
{
	return ctx->priv->status == CTX_STATE_DISPATCHED;
}

static inline bool ctx_is_connected(struct amdxdna_ctx *ctx)
{
	return ctx->priv->status == CTX_STATE_CONNECTED;
}

static inline bool ctx_is_disconnecting(struct amdxdna_ctx *ctx)
{
	return ctx->priv->status == CTX_STATE_DISCONNECTING;
}

static inline bool ctx_should_stop(struct amdxdna_ctx *ctx)
{
	return ctx_is_connected(ctx) ||
		ctx_is_disconnecting(ctx) ||
		ctx_is_debug(ctx);
}

static inline bool rq_connect_is_full(struct aie2_ctx_rq *rq)
{
	WARN_ON(rq->hwctx_cnt > rq->hwctx_limit);
	return rq->hwctx_cnt == rq->hwctx_limit;
}

static struct amdxdna_ctx *
select_next_ctx(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct list_head *q;
	int i;

	if (!rq->runqueue_total)
		return NULL;

	i = 0;
	if (ctx) {
		if (list_is_last(&ctx->entry, &rq->runqueue[ctx->qos.priority - 1].q))
			i = ctx->qos.priority;
		else
			return list_next_entry(ctx, entry);
	}

	while (i < ARRAY_SIZE(rq->runqueue)) {
		q = &rq->runqueue[i].q;

		if (!rq->runqueue[i].cnt) {
			i++;
			continue;
		}

		return list_first_entry(q, typeof(*ctx), entry);
	}

	return NULL;
}

static struct amdxdna_ctx *
select_highest_prio_ctx(struct aie2_ctx_rq *rq)
{
	return select_next_ctx(rq, NULL);
}

/*
 * The connected context list is ordered. Use this helper function to
 * maintain the ordering. Use linux list_move*, list_del for removing.
 * The rule for ordering,
 * 1. From rq->conn_list head, context is ordered by priority from high to low
 * 2. For same priority contexts, ordered from new to old
 *
 * This rule make it easy to look for lowest and oldest priority context.
 */
static void
insert_ctx_to_conn_list(struct aie2_ctx_rq *rq, struct amdxdna_ctx *new)
{
	struct amdxdna_ctx *curr;
	struct list_head *pos;

	if (list_empty(&rq->conn_list)) {
		pos = &rq->conn_list;
		goto out;
	}

	curr = list_last_entry(&rq->conn_list, typeof(*curr), entry);
	if (curr->qos.priority < new->qos.priority) {
		pos = &rq->conn_list;
		goto out;
	}

	list_for_each_entry(curr, &rq->conn_list, entry) {
		if (curr->qos.priority < new->qos.priority)
			continue;

		/* Insert new context before current */
		pos = &curr->entry;
		break;
	}

out:
	list_move_tail(&new->entry, pos);
	rq->hwctx_cnt++;
}

static struct amdxdna_ctx *
select_ctx_to_block(struct aie2_ctx_rq *rq, int prio)
{
	struct amdxdna_ctx *ctx;

	list_for_each_entry_reverse(ctx, &rq->conn_list, entry) {
		if (ctx->qos.priority < prio)
			continue;

		if (ctx->priv->should_block)
			continue;

		return ctx;
	}

	return NULL;
}

static void rq_ctx_start(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;
	int err;

	xdna = ctx_rq_to_xdna_dev(rq);
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	drm_WARN_ON(&xdna->ddev, !rwsem_is_locked(&ctx->priv->io_sem));
	err = aie2_ctx_connect(ctx);
	if (err) {
		list_move_tail(&ctx->entry, &rq->disconn_list);
		ctx->priv->status = CTX_STATE_DEAD;
		XDNA_ERR(xdna, "%s connect failed, err %d", ctx->name, err);
	} else {
		insert_ctx_to_conn_list(rq, ctx);
		ctx->priv->status = CTX_STATE_CONNECTED;
		XDNA_DBG(xdna, "%s connected", ctx->name);
	}

	rq->runqueue[ctx->qos.priority - 1].cnt--;
	rq->runqueue_total--;
}

static void rq_ctx_stop_wait(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx, bool wait)
{
	struct amdxdna_dev *xdna;

	xdna = ctx_rq_to_xdna_dev(rq);
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	drm_WARN_ON(&xdna->ddev, !rwsem_is_locked(&ctx->priv->io_sem));
	if (!ctx_should_stop(ctx)) {
		XDNA_DBG(xdna, "%s skip stop, status %d", ctx->name, ctx->priv->status);
		return;
	}
	aie2_ctx_disconnect(ctx, wait);
	list_move_tail(&ctx->entry, &rq->disconn_list);
	rq->hwctx_cnt--;
	ctx->priv->status = CTX_STATE_DISCONNECTED;
	XDNA_DBG(xdna, "%s disconnected", ctx->name);
}

static void rq_ctx_stop(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	rq_ctx_stop_wait(rq, ctx, true);
}

static void rq_ctx_dispatch(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;
	int prio_q;

	xdna = ctx_rq_to_xdna_dev(rq);
	prio_q = ctx->qos.priority - 1;
	list_move_tail(&ctx->entry, &rq->runqueue[prio_q].q);
	ctx->priv->status = CTX_STATE_DISPATCHED;
	rq->runqueue[prio_q].cnt++;
	rq->runqueue_total++;
	XDNA_DBG(xdna, "%s dispatched, priority queue %d", ctx->name, prio_q);
}

static void rq_ctx_cancel(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;
	int prio_q;

	xdna = ctx_rq_to_xdna_dev(rq);
	prio_q = ctx->qos.priority - 1;
	list_move_tail(&ctx->entry, &rq->runqueue[prio_q].q);
	list_move_tail(&ctx->entry, &rq->disconn_list);
	ctx->priv->status = CTX_STATE_DISCONNECTED;
	rq->runqueue[prio_q].cnt--;
	rq->runqueue_total--;
	XDNA_DBG(xdna, "%s cancelled", ctx->name);
}

static void rq_sched_work(struct work_struct *work)
{
	struct aie2_ctx_rq *rq;
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *next;
	struct amdxdna_ctx *curr;

	rq = container_of(work, struct aie2_ctx_rq, sched_work);
	xdna = ctx_rq_to_xdna_dev(rq);

	XDNA_DBG(xdna, "start");
	mutex_lock(&xdna->dev_lock);
	do {
		next = select_highest_prio_ctx(rq);
		if (!next)
			break;

		if (rq_connect_is_full(rq))
			break;

		down_write(&next->priv->io_sem);
		rq_ctx_start(rq, next);
		wake_up_all(&next->priv->connect_waitq);
		up_write(&next->priv->io_sem);
	} while (1);

	if (!rq_connect_is_full(rq)) {
		mutex_unlock(&xdna->dev_lock);
		return;
	}

	while (next) {
		curr = select_ctx_to_block(rq, next->qos.priority);
		if (!curr)
			break;

		XDNA_DBG(xdna, "block %s, next %s", curr->name, next->name);
		curr->priv->should_block = true;
		down_write(&curr->priv->io_sem);
		if (!atomic64_read(&curr->priv->job_pending_cnt) &&
		    curr->submitted == curr->completed) {
			curr->priv->status = CTX_STATE_DISCONNECTING;
			queue_work(rq->work_q, &curr->yield_work);
		}
		up_write(&curr->priv->io_sem);

		next = select_next_ctx(rq, next);
	}
	mutex_unlock(&xdna->dev_lock);
}

static void rq_dispatch_work(struct work_struct *work)
{
	struct aie2_ctx_rq *rq;
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;

	ctx = container_of(work, struct amdxdna_ctx, dispatch_work);
	xdna = ctx->client->xdna;
	rq = &xdna->dev_handle->ctx_rq;

	XDNA_DBG(xdna, "%s dispatch work", ctx->name);
	mutex_lock(&xdna->dev_lock);
	down_write(&ctx->priv->io_sem);
	if (ctx_is_disconnected(ctx)) {
		rq_ctx_dispatch(rq, ctx);
		queue_work(rq->work_q, &rq->sched_work);
	}
	up_write(&ctx->priv->io_sem);
	mutex_unlock(&xdna->dev_lock);
}

static void rq_yield_work(struct work_struct *work)
{
	struct aie2_ctx_rq *rq;
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;

	ctx = container_of(work, struct amdxdna_ctx, yield_work);
	xdna = ctx->client->xdna;
	rq = &xdna->dev_handle->ctx_rq;

	XDNA_DBG(xdna, "%s yield work", ctx->name);
	mutex_lock(&xdna->dev_lock);
	down_write(&ctx->priv->io_sem);
	if (ctx->submitted != ctx->completed)
		goto out;

	ctx->priv->should_block = false;
	if (!rq->runqueue_total) {
		ctx->priv->status = CTX_STATE_CONNECTED;
		wake_up_all(&ctx->priv->connect_waitq);
		goto out;
	}

	rq_ctx_stop(rq, ctx);
	queue_work(rq->work_q, &rq->sched_work);
out:
	up_write(&ctx->priv->io_sem);
	mutex_unlock(&xdna->dev_lock);
}

/*
 * aie2_rq_is_all_context_stuck - Check if all connected contexts stuck
 *
 * This function is helpful to implement TDR (Timeout Detecting & Recovering).
 * Return true when all running context(s) did NOT making progress. Otherwise
 * return false.
 *
 * Where running context is
 *   - A connected context
 *   - A context with outstanding commands
 *
 * Where making progress context is
 *   - Completed counter changed from last check
 *
 * NOTE: Based on above definition, caller needs to call this twice to know if
 * all context stuck. It is caller determine when to call.
 */
bool aie2_rq_is_all_context_stuck(struct aie2_ctx_rq *rq)
{
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	int progress_cnt = 0;
	int running_cnt = 0;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	list_for_each_entry(ctx, &rq->conn_list, entry) {
		u64 completed = ctx->completed;
		u64 last = ctx->last_completed;
		u64 submitted = ctx->submitted;

		XDNA_DBG(xdna, "%s submitted %lld completed %lld last %lld",
			 ctx->name, submitted, completed, last);
		if (submitted == completed)
			continue;

		running_cnt++;
		if (last != completed) {
			ctx->last_completed = completed;
			progress_cnt++;
		}
	}
	mutex_unlock(&xdna->dev_lock);

	return running_cnt && !progress_cnt;
}

bool aie2_rq_handle_idle_ctx(struct aie2_ctx_rq *rq)
{
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	bool found = false;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	list_for_each_entry(ctx, &rq->conn_list, entry) {
		u64 completed = ctx->completed;
		u64 submitted;

		down_write(&ctx->priv->io_sem);
		submitted = ctx->submitted;
		if (submitted == completed)
			ctx->priv->idle_cnt++;
		else
			ctx->priv->idle_cnt = 0;

		if (ctx->priv->idle_cnt == RQ_CTX_IDLE_COUNT) {
			ctx->priv->idle_cnt = 0;
			queue_work(rq->work_q, &ctx->yield_work);
			XDNA_DBG(xdna, "%s idle, try swap out", ctx->name);
			found = true;
		}
		up_write(&ctx->priv->io_sem);
	}
	mutex_unlock(&xdna->dev_lock);

	return found;
}

void aie2_rq_pause_all_nolock(struct aie2_ctx_rq *rq)
{
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	struct amdxdna_ctx *tmp;

	xdna = ctx_rq_to_xdna_dev(rq);
	WARN_ON(rq->paused);

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	list_for_each_entry_safe(ctx, tmp, &rq->conn_list, entry) {
		down_write(&ctx->priv->io_sem);
		XDNA_DBG(xdna, "%s pause", ctx->name);
		rq_ctx_stop_wait(rq, ctx, false);
		up_write(&ctx->priv->io_sem);
	}

	rq->paused = true;
}

void aie2_rq_run_all_nolock(struct aie2_ctx_rq *rq)
{
	struct amdxdna_dev *xdna;

	xdna = ctx_rq_to_xdna_dev(rq);
	WARN_ON(!rq->paused);

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	queue_work(rq->work_q, &rq->sched_work);

	rq->paused = false;
}

/*
 * aie2_rq_pause_all - Disconnect all context
 *
 * This can be used in suspend/resume flow or whenever temporarily stop all
 * the connecting contexts is needed.
 */
void aie2_rq_pause_all(struct aie2_ctx_rq *rq)
{
	struct amdxdna_dev *xdna;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	aie2_rq_pause_all_nolock(rq);
	mutex_unlock(&xdna->dev_lock);
}

/*
 * aie2_rq_run_all - Connect all pause context
 *
 * This shoudl be called after aie2_rq_pause_all() to rerun all paused context.
 */
void aie2_rq_run_all(struct aie2_ctx_rq *rq)
{
	struct amdxdna_dev *xdna;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	aie2_rq_run_all_nolock(rq);
	mutex_unlock(&xdna->dev_lock);
}

/* This is called when command completed. Do NOT hold lock */
void aie2_rq_yield(struct amdxdna_ctx *ctx)
{
	struct aie2_ctx_rq *rq;

	if (!ctx->priv->should_block)
		return;

	rq = &ctx->client->xdna->dev_handle->ctx_rq;
	ctx->priv->status = CTX_STATE_DISCONNECTING;
	if (ctx->submitted == ctx->completed)
		queue_work(rq->work_q, &ctx->yield_work);
}

static int rq_submit_enter_slow(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;
	int ret;

	xdna = ctx_rq_to_xdna_dev(rq);

	atomic64_inc(&ctx->priv->job_pending_cnt);
	queue_work(rq->work_q, &ctx->dispatch_work);
	ret = wait_event_interruptible(ctx->priv->connect_waitq,
				       ctx_is_connected(ctx) || ctx_is_fatal(ctx));
	if (ret)
		goto exit_and_cleanup;

	if (ctx_is_fatal(ctx)) {
		atomic64_dec(&ctx->priv->job_pending_cnt);
		return -EIO;
	}

	/*
	 * If a context is on connected list. It will retain connection until
	 * this context call aie2_rq_yield().
	 * At this point, this context will not be swapped out.
	 */
	down_read(&ctx->priv->io_sem);
	atomic64_dec(&ctx->priv->job_pending_cnt);
	return 0;

exit_and_cleanup:
	cancel_work_sync(&ctx->dispatch_work);

	atomic64_dec(&ctx->priv->job_pending_cnt);
	mutex_lock(&xdna->dev_lock);
	down_write(&ctx->priv->io_sem);
	if (ctx_is_dispatched(ctx))
		rq_ctx_cancel(rq, ctx);
	if (ctx_is_connected(ctx))
		rq_ctx_stop(rq, ctx);
	up_write(&ctx->priv->io_sem);
	mutex_unlock(&xdna->dev_lock);

	queue_work(rq->work_q, &rq->sched_work);

	return ret;
}

int aie2_rq_submit_enter(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;

	xdna = ctx_rq_to_xdna_dev(rq);
	down_read(&ctx->priv->io_sem);
	if (ctx_is_connected(ctx))
		return 0;

	if (ctx_is_fatal(ctx)) {
		up_read(&ctx->priv->io_sem);
		return -EIO;
	}

	/* Slow path */
	up_read(&ctx->priv->io_sem);
	return rq_submit_enter_slow(rq, ctx);
}

void aie2_rq_submit_exit(struct amdxdna_ctx *ctx)
{
	up_read(&ctx->priv->io_sem);
}

int aie2_rq_add(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	if (rq->ctx_limit == rq->ctx_cnt) {
		mutex_unlock(&xdna->dev_lock);
		XDNA_ERR(xdna, "Not allow more than %d context(s)", rq->ctx_limit);
		return -ENOENT;
	}

	INIT_WORK(&ctx->dispatch_work, rq_dispatch_work);
	INIT_WORK(&ctx->yield_work, rq_yield_work);
	ctx->priv->status = CTX_STATE_DISCONNECTED;
	ctx->priv->should_block = false;

	list_add_tail(&ctx->entry, &rq->disconn_list);
	rq->ctx_cnt++;
	mutex_unlock(&xdna->dev_lock);
	XDNA_DBG(xdna, "%s added, status %d", ctx->name, ctx->priv->status);
	return 0;
}

void aie2_rq_del(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	down_write(&ctx->priv->io_sem);
	rq_ctx_stop(rq, ctx);
	up_write(&ctx->priv->io_sem);
	list_del(&ctx->entry);
	rq->ctx_cnt--;
	mutex_unlock(&xdna->dev_lock);
	cancel_work_sync(&ctx->yield_work);
	XDNA_DBG(xdna, "%s deleted, status %d", ctx->name, ctx->priv->status);
}

int aie2_rq_init(struct aie2_ctx_rq *rq)
{
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;
	int i;

	ndev = ctx_rq_to_ndev(rq);
	xdna = ndev->xdna;
	/* amdxdna_dev_ops.init() set default context and connect limit value */
	if (context_limit)
		rq->ctx_limit = context_limit;
	else
		rq->ctx_limit = ndev->priv->ctx_limit;

	if (hwctx_limit)
		rq->hwctx_limit = hwctx_limit;
	else
		rq->hwctx_limit = ndev->priv->hwctx_limit;
	XDNA_DBG(xdna, "Maximum limit %d virtual context(s)", rq->ctx_limit);
	XDNA_DBG(xdna, "Maximum limit %d hardware context(s)", rq->hwctx_limit);

	if (!rq->ctx_limit || !rq->hwctx_limit) {
		XDNA_ERR(xdna, "Zero context or hwctx limit");
		return -EINVAL;
	}

	rq->work_q = alloc_ordered_workqueue("ctx_runqueue", 0);
	if (!rq->work_q)
		return -ENOMEM;

	INIT_WORK(&rq->sched_work, rq_sched_work);
	INIT_LIST_HEAD(&rq->conn_list);
	INIT_LIST_HEAD(&rq->disconn_list);
	for (i = 0; i < ARRAY_SIZE(rq->runqueue); i++)
		INIT_LIST_HEAD(&rq->runqueue[i].q);
	rq->paused = false;

	return 0;
}

void aie2_rq_fini(struct aie2_ctx_rq *rq)
{
	destroy_workqueue(rq->work_q);
}
