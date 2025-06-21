// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#if defined(CONFIG_DEBUG_FS)
#include <linux/seq_file.h>
#endif
#include "amdxdna_drm.h"
#include "aie2_pci.h"

uint context_limit;
module_param(context_limit, uint, 0444);
MODULE_PARM_DESC(context_limit, "Maximum number of context, 0 = Use default");

uint hwctx_limit;
module_param(hwctx_limit, uint, 0444);
MODULE_PARM_DESC(hwctx_limit, "[Debug] Maximum number of hwctx. 0 = Use default");

bool wait_update_parts = true;
module_param(wait_update_parts, bool, 0600);
MODULE_PARM_DESC(wait_update_parts, "[Debug] Add/Del context wait for update partition");

#define RQ_CTX_IDLE_COUNT 3

#if AMDXDNA_NUM_PRIORITY != CTX_RQ_NUM_QUEUE
#error "AMDXDNA_NUM_PRIORITY not equals to CTX_RQ_NUM_QUEUE"
#endif
static void qos_to_rq_prio(struct amdxdna_ctx *ctx)
{
	u32 *rq_prio = &ctx->priv->priority;
	u32 *qos = &ctx->qos.priority;

	switch (*qos) {
	case AMDXDNA_QOS_REALTIME_PRIORITY:
		*rq_prio = CTX_RQ_REALTIME;
		break;
	case AMDXDNA_QOS_HIGH_PRIORITY:
		*rq_prio = CTX_RQ_HIGH;
		break;
	case AMDXDNA_QOS_NORMAL_PRIORITY:
		*rq_prio = CTX_RQ_NORMAL;
		break;
	case AMDXDNA_QOS_LOW_PRIORITY:
		*rq_prio = CTX_RQ_LOW;
		break;
	default:
		*qos = AMDXDNA_QOS_NORMAL_PRIORITY;
		*rq_prio = CTX_RQ_NORMAL;
	};
}

static inline bool ctx_is_rt(struct amdxdna_ctx *ctx)
{
	return ctx->priv->priority == CTX_RQ_REALTIME;
}

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

static inline u32 part_max_non_rt_hwctx(struct aie2_partition *part)
{
	return part->max_hwctx - part->max_rt_ctx;
}

static inline bool part_connect_is_full(struct aie2_partition *part)
{
	int non_rt_hwctx;

	non_rt_hwctx = part->hwctx_cnt - part->rt_ctx_cnt;
	WARN_ON(non_rt_hwctx > part_max_non_rt_hwctx(part));
	return non_rt_hwctx == part_max_non_rt_hwctx(part);
}

static inline u32
part_num_col(struct aie2_partition *part)
{
	return part->end_col - part->start_col + 1;
}

static void
part_ctx_dispatch(struct aie2_partition *part, struct amdxdna_ctx *ctx)
{
	int prio_q = ctx->priv->priority;

	list_move_tail(&ctx->entry, &part->runqueue[prio_q]);
	part->ctx_cnt++;
	if (ctx_is_rt(ctx))
		part->rt_ctx_cnt++;

	ctx->priv->status = CTX_STATE_DISPATCHED;
	ctx->priv->part = part;
	ctx->priv->active = true; /* Dispatch context is counted as an activity */
	ctx->priv->idle_cnt = 0;
	XDNA_DBG(ctx->client->xdna, "%s dispatched, priority queue %d", ctx->name, prio_q);
}

static bool part_handle_idle_ctx(struct aie2_partition *part, bool force)
{
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	bool found = false;

	xdna = ctx_rq_to_xdna_dev(part->rq);
	if (!part->hwctx_cnt)
		return false;

	list_for_each_entry(ctx, &part->conn_list, entry) {
		u64 completed = ctx->completed;
		u64 submitted;

		down_write(&ctx->priv->io_sem);
		submitted = ctx->submitted;
		if (submitted == completed)
			ctx->priv->idle_cnt++;
		else
			ctx->priv->idle_cnt = 0;

		if (ctx->priv->idle_cnt == RQ_CTX_IDLE_COUNT ||
		    (ctx->priv->idle_cnt && force)) {
			XDNA_DBG(xdna, "%s idle, cnt %d try swap out",
				 ctx->name, ctx->priv->idle_cnt);
			ctx->priv->force_yield = true;
			ctx->priv->status = CTX_STATE_DISCONNECTING;
			ctx->priv->active = false;
			ctx->priv->idle_cnt = 0;
			queue_work(part->rq->work_q, &ctx->yield_work);
			found = true;
		}
		up_write(&ctx->priv->io_sem);
	}

	return found;
}

static bool
part_is_all_ctx_stuck(struct aie2_partition *part)
{
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	int progress_cnt = 0;
	int running_cnt = 0;

	xdna = ctx_rq_to_xdna_dev(part->rq);
	list_for_each_entry(ctx, &part->conn_list, entry) {
		u64 completed = ctx->completed;
		u64 last = ctx->last_completed;
		u64 submitted = ctx->submitted;

		XDNA_DBG(xdna, "%s @[%d, %d] submitted %lld completed %lld last %lld",
			 ctx->name, part->start_col, part->end_col,
			 submitted, completed, last);
		if (submitted == completed)
			continue;

		running_cnt++;
		if (last != completed) {
			ctx->last_completed = completed;
			progress_cnt++;
		}
	}

	return running_cnt && !progress_cnt;
}

static struct aie2_partition *
rq_part_rt_select(struct aie2_ctx_rq *rq)
{
	struct aie2_partition *min = NULL;
	struct aie2_partition *part;
	int i;

	for (i = 0; i < rq->num_parts; i++) {
		part = &rq->parts[i];
		if (part->rt_ctx_cnt == part->max_rt_ctx)
			continue;

		if (!min) {
			min = part;
			continue;
		}

		if (min->rt_ctx_cnt > part->rt_ctx_cnt)
			min = part;
	}

	return min;
}

static struct aie2_partition *
rq_part_non_rt_select(struct aie2_ctx_rq *rq)
{
	struct aie2_partition *min = NULL;
	struct aie2_partition *part;
	int i;

	for (i = 0; i < rq->num_parts; i++) {
		part = &rq->parts[i];
		if (part->max_hwctx == part->max_rt_ctx)
			continue;

		if (!min) {
			min = part;
			continue;
		}

		if (part->ctx_cnt > min->ctx_cnt)
			continue;

		if (part->ctx_cnt < min->ctx_cnt) {
			min = part;
			continue;
		}

		if (min->max_rt_ctx > part->max_rt_ctx)
			min = part;
	}

	return min;
}

static struct aie2_partition *
rq_part_select(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	if (ctx_is_rt(ctx))
		return rq_part_rt_select(rq);
	else
		return rq_part_non_rt_select(rq);
}

static struct amdxdna_ctx *
select_next_ctx(struct aie2_partition *part, struct amdxdna_ctx *ctx)
{
	struct amdxdna_ctx *ret = NULL;
	struct list_head *q;
	int i;

	if (part->ctx_cnt == part->hwctx_cnt)
		return NULL;

	i = 0;
	if (ctx) {
		q = &part->runqueue[ctx->priv->priority];
		if (list_is_last(&ctx->entry, q)) {
			i = ctx->priv->priority + 1; /* next queue */
		} else {
			ret = list_next_entry(ctx, entry);
			goto out;
		}
	}

	while (i < ARRAY_SIZE(part->runqueue)) {
		q = &part->runqueue[i];

		if (!list_empty(q)) {
			ret = list_first_entry(q, typeof(*ctx), entry);
			break;
		}

		i++;
	}

out:
	return ret;
}

static struct amdxdna_ctx *
select_highest_prio_ctx(struct aie2_partition *part)
{
	return select_next_ctx(part, NULL);
}

/*
 * The connected context list is ordered. Use this helper function to
 * maintain the ordering. Use linux list_move*, list_del for removing.
 * The rule for ordering,
 * 1. From conn_list head, context is ordered by priority from high to low
 * 2. For same priority contexts, ordered from new to old
 *
 * This rule make it easy to look for lowest and oldest priority context.
 */
static void
insert_ctx_to_conn_list(struct aie2_partition *part, struct amdxdna_ctx *new)
{
	struct amdxdna_ctx *curr;
	struct list_head *pos;

	if (list_empty(&part->conn_list)) {
		pos = &part->conn_list;
		goto out;
	}

	curr = list_last_entry(&part->conn_list, typeof(*curr), entry);
	if (curr->priv->priority < new->priv->priority) {
		pos = &part->conn_list;
		goto out;
	}

	list_for_each_entry(curr, &part->conn_list, entry) {
		if (curr->priv->priority < new->priv->priority)
			continue;

		/* Insert new context before current */
		pos = &curr->entry;
		break;
	}

out:
	list_move_tail(&new->entry, pos);
	part->hwctx_cnt++;
}

static struct amdxdna_ctx *
select_ctx_to_block(struct aie2_partition *part, int prio)
{
	struct amdxdna_ctx *ctx;

	list_for_each_entry_reverse(ctx, &part->conn_list, entry) {
		if (ctx->priv->priority < prio)
			continue;

		if (ctx->priv->should_block)
			continue;

		return ctx;
	}

	return NULL;
}

static void part_ctx_start(struct aie2_partition *part, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;
	int err;

	xdna = ctx_rq_to_xdna_dev(part->rq);

	down_write(&ctx->priv->io_sem);
	ctx->start_col = part->start_col;
	ctx->num_col = part_num_col(part);
	err = aie2_ctx_connect(ctx);
	if (err) {
		ctx->priv->status = CTX_STATE_DEAD;
		ctx->priv->errno = err;
		up_write(&ctx->priv->io_sem);
		XDNA_ERR(xdna, "%s connect failed, err %d", ctx->name, err);
		goto ctx_dead;
	}

	insert_ctx_to_conn_list(part, ctx);
	ctx->priv->status = CTX_STATE_CONNECTED;
	XDNA_DBG(xdna, "%s connected", ctx->name);
	up_write(&ctx->priv->io_sem);
	return;

ctx_dead:
	list_move_tail(&ctx->entry, &part->rq->disconn_list);
	part->ctx_cnt--;
	if (ctx_is_rt(ctx))
		part->rt_ctx_cnt--;
	ctx->priv->part = NULL;
}

static void part_ctx_stop_wait(struct amdxdna_ctx *ctx, bool wait)
{
	struct aie2_partition *part;
	struct amdxdna_dev *xdna;
	struct aie2_ctx_rq *rq;

	xdna = ctx->client->xdna;
	rq = &xdna->dev_handle->ctx_rq;
	drm_WARN_ON(&xdna->ddev, !rwsem_is_locked(&ctx->priv->io_sem));
	if (!ctx_should_stop(ctx)) {
		XDNA_DBG(xdna, "%s skip stop, status %d", ctx->name, ctx->priv->status);
		return;
	}
	aie2_ctx_disconnect(ctx, wait);

	list_move_tail(&ctx->entry, &rq->disconn_list);
	ctx->priv->status = CTX_STATE_DISCONNECTED;

	part = ctx->priv->part;
	if (part) {
		part->hwctx_cnt--;
		part->ctx_cnt--;
		if (ctx_is_rt(ctx))
			part->rt_ctx_cnt--;
	}
	ctx->priv->part = NULL;
	ctx->priv->idle_cnt = 0;
	XDNA_DBG(xdna, "%s disconnected", ctx->name);
}

static void rq_ctx_cancel(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct aie2_partition *part;
	struct amdxdna_dev *xdna;
	int prio_q;

	part = ctx->priv->part;
	xdna = ctx_rq_to_xdna_dev(rq);

	down_write(&ctx->priv->io_sem);
	prio_q = ctx->priv->priority;
	list_move_tail(&ctx->entry, &rq->disconn_list);
	ctx->priv->status = CTX_STATE_DISCONNECTED;
	part = ctx->priv->part;
	if (part) {
		part->ctx_cnt--;
		if (ctx_is_rt(ctx))
			part->rt_ctx_cnt--;
	}
	ctx->priv->part = NULL;
	up_write(&ctx->priv->io_sem);

	XDNA_DBG(xdna, "%s cancelled", ctx->name);
}

static void part_block_all_ctx(struct aie2_partition *part)
{
	struct amdxdna_ctx *ctx;

	list_for_each_entry(ctx, &part->conn_list, entry) {
		XDNA_DBG(ctx->client->xdna, "%s set block", ctx->name);
		ctx->priv->should_block = true;
	}
}

static void part_cleanup(struct aie2_partition *part)
{
	struct amdxdna_ctx *ctx, *tmp;
	struct amdxdna_dev *xdna;
	struct aie2_ctx_rq *rq;
	struct list_head *q;
	int i;

	WARN_ON(part->hwctx_cnt);
	if (!part->ctx_cnt)
		return;

	rq = part->rq;
	xdna = ctx_rq_to_xdna_dev(rq);
	XDNA_DBG(xdna, "Part [%d %d]", part->start_col, part->end_col);
	for (i = 0; i < ARRAY_SIZE(part->runqueue); i++) {
		q = &part->runqueue[i];
		list_for_each_entry_safe(ctx, tmp, q, entry) {
			list_move_tail(&ctx->entry, &rq->disconn_list);
			part->ctx_cnt--;
			if (ctx_is_rt(ctx))
				part->rt_ctx_cnt--;
			ctx->priv->status = CTX_STATE_DISCONNECTED;
			ctx->priv->part = NULL;
			queue_work(rq->work_q, &ctx->dispatch_work);
		}
	}
}

static void part_sched_work(struct work_struct *work)
{
	struct aie2_partition *part;
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *next;
	struct amdxdna_ctx *curr;
	struct aie2_ctx_rq *rq;

	part = container_of(work, struct aie2_partition, sched_work);
	xdna = ctx_rq_to_xdna_dev(part->rq);
	rq = part->rq;

	mutex_lock(&xdna->dev_lock);
	XDNA_DBG(xdna, "partition [%d, %d] max_hwctx %d hwctx %d cnt %d",
		 part->start_col, part->end_col, part->max_hwctx,
		 part->hwctx_cnt, part->ctx_cnt);
	if (part->rq->paused)
		goto out;

	do {
		next = select_highest_prio_ctx(part);
		if (!next)
			break;

		if (!ctx_is_rt(next) && part_connect_is_full(part))
			break;

		part_ctx_start(part, next);
		wake_up_all(&next->priv->connect_waitq);
	} while (1);

	if (!part_connect_is_full(part))
		goto out;

	while (next) {
		curr = select_ctx_to_block(part, next->priv->priority);
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

		next = select_next_ctx(part, next);
	}
out:
	mutex_unlock(&xdna->dev_lock);
}

static void rq_yield_work(struct work_struct *work)
{
	struct aie2_partition *part;
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	struct aie2_ctx_rq *rq;

	ctx = container_of(work, struct amdxdna_ctx, yield_work);
	xdna = ctx->client->xdna;

	mutex_lock(&xdna->dev_lock);
	down_write(&ctx->priv->io_sem);
	XDNA_DBG(xdna, "%s yield work", ctx->name);
	part = ctx->priv->part;
	if (!part)
		goto out;

	if (ctx->submitted != ctx->completed)
		goto out;

	rq = part->rq;
	if (part->ctx_cnt <= part->hwctx_cnt && !ctx->priv->force_yield && !rq->paused) {
		if (!part_connect_is_full(part))
			ctx->priv->should_block = false;
		ctx->priv->status = CTX_STATE_CONNECTED;
		wake_up_all(&ctx->priv->connect_waitq);
		goto out;
	}

	ctx->priv->should_block = false;
	part_ctx_stop_wait(ctx, true);
	if (rq->paused)
		queue_work(rq->work_q, &rq->parts_work);
	else
		queue_work(rq->work_q, &part->sched_work);
	if (atomic64_read(&ctx->priv->job_pending_cnt))
		queue_work(rq->work_q, &ctx->dispatch_work);
out:
	ctx->priv->force_yield = false;
	up_write(&ctx->priv->io_sem);
	mutex_unlock(&xdna->dev_lock);
}

static void rq_dispatch_work(struct work_struct *work)
{
	struct aie2_partition *part;
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	struct aie2_ctx_rq *rq;

	ctx = container_of(work, struct amdxdna_ctx, dispatch_work);
	xdna = ctx->client->xdna;
	rq = &xdna->dev_handle->ctx_rq;

	mutex_lock(&xdna->dev_lock);
	down_write(&ctx->priv->io_sem);
	XDNA_DBG(xdna, "Dispatching %s status %d QoS priority %d",
		 ctx->name, ctx->priv->status, ctx->priv->priority);
	if (!ctx_is_disconnected(ctx))
		goto out;

	if (rq->paused) {
		XDNA_DBG(xdna, "Paused %s delay dispatch", ctx->name);
		goto out;
	}

	part = rq_part_select(rq, ctx);
	WARN_ON(!part);
	XDNA_DBG(xdna, "%s -> partition [%d, %d]",
		 ctx->name, part->start_col, part->end_col);
	part_ctx_dispatch(part, ctx);
	queue_work(rq->work_q, &part->sched_work);
out:
	up_write(&ctx->priv->io_sem);
	mutex_unlock(&xdna->dev_lock);
}

static void rq_part_ctx_limit_calc(struct aie2_ctx_rq *rq, int i)
{
	struct aie2_partition *part;
	int average_rt;
	int more_rt_i;

	part = &rq->parts[i];
	average_rt = rq->rt_ctx_cnt / rq->num_parts;
	more_rt_i = rq->rt_ctx_cnt - average_rt * rq->num_parts;

	part->max_hwctx = rq->hwctx_limit / rq->num_parts;
	if (i < more_rt_i)
		part->max_rt_ctx = average_rt + 1;
	else
		part->max_rt_ctx = average_rt;
	WARN_ON(part->max_rt_ctx > part->max_hwctx);
}

static void rq_part_reinit(struct aie2_ctx_rq *rq, bool all)
{
	struct aie2_partition *part;
	struct amdxdna_dev *xdna;
	u32 num_col;
	int i, j;

	xdna = ctx_rq_to_xdna_dev(rq);
	num_col = (rq->max_cols) ? rq->max_cols : 1;
	rq->num_parts = min(rq->total_cols / num_col, rq->hwctx_limit);
	WARN_ON(!rq->num_parts);
	for (i = 0; i < rq->num_parts; i++) {
		part = &rq->parts[i];
		WARN_ON(part->ctx_cnt);
		WARN_ON(part->hwctx_cnt);
		part->start_col = rq->start_col + i * num_col;
		part->end_col = part->start_col + num_col - 1;
		rq_part_ctx_limit_calc(rq, i);
		XDNA_DBG(xdna, "Part [%d, %d] max hwctx %d max rt ctx %d",
			 part->start_col, part->end_col, part->max_hwctx,
			 part->max_rt_ctx);

		if (!all)
			continue;

		XDNA_DBG(xdna, "Part [%d, %d] init all",
			 part->start_col, part->end_col);
		part->rq = rq;
		INIT_LIST_HEAD(&part->conn_list);
		for (j = 0; j < ARRAY_SIZE(part->runqueue); j++)
			INIT_LIST_HEAD(&part->runqueue[j]);
		INIT_WORK(&part->sched_work, part_sched_work);
	}
	rq->max_cols = num_col;
}

#define rq_part_resize(rq) rq_part_reinit(rq, false)
#define rq_part_init(rq) rq_part_reinit(rq, true)

static inline u32 get_part_cols(struct aie2_partition *p)
{
	return p->end_col - p->start_col + 1;
}

static bool should_update_parts(struct aie2_ctx_rq *rq)
{
	struct amdxdna_dev *xdna;
	u32 part_rt_ctx = 0;
	u32 part_ctx = 0;
	u32 part_col;
	int i;

	xdna = ctx_rq_to_xdna_dev(rq);
	part_col = get_part_cols(&rq->parts[0]);
	for (i = 0; i < rq->num_parts; i++) {
		part_rt_ctx += rq->parts[i].max_rt_ctx;
		part_ctx += rq->parts[i].ctx_cnt;
	}

	XDNA_DBG(xdna, "max_cols %d part_col %d rt_ctx %d part_rt_ctx %d",
		 rq->max_cols, part_col, rq->rt_ctx_cnt, part_rt_ctx);

	/* rq is paused, go update */
	if (rq->paused && !part_ctx)
		return true;

	rq->max_cols = xdna->dev_handle->total_col;
	while (rq->max_cols) {
		if (rq->ctx_width_resv[rq->max_cols])
			break;

		rq->max_cols--;
	}

	if (rq->max_cols != part_col)
		return true;

	/*
	 * When max cols not equals to partition cols,
	 * it needs to update partition cols to new max cols.
	 */
	if (rq->rt_ctx_cnt != part_rt_ctx)
		return true;

	return false;
}

static bool handle_busy_ctxs(struct aie2_ctx_rq *rq)
{
	struct aie2_partition *part;
	bool active = false;
	int i;

	for (i = 0; i < rq->num_parts; i++) {
		part = &rq->parts[i];
		if (!part->hwctx_cnt)
			continue;

		active = true;
		part_block_all_ctx(part);
		part_handle_idle_ctx(part, true);
	}

	return active;
}

static void rq_parts_work(struct work_struct *work)
{
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	struct amdxdna_ctx *tmp;
	struct aie2_ctx_rq *rq;
	int i;

	rq = container_of(work, struct aie2_ctx_rq, parts_work);
	xdna = ctx_rq_to_xdna_dev(rq);

	mutex_lock(&xdna->dev_lock);
	if (!should_update_parts(rq))
		goto out;

	/* Partition expanding or trimming is needed */
	rq->paused = true;
	if (handle_busy_ctxs(rq)) {
		XDNA_DBG(xdna, "Wait for disconneting active contexts");
		goto out;
	}

	for (i = 0; i < rq->num_parts; i++)
		part_cleanup(&rq->parts[i]);

	rq_part_resize(rq);
	rq->paused = false;
	list_for_each_entry_safe(ctx, tmp, &rq->parts_work_waitq, parts_work_entry) {
		list_del_init(&ctx->parts_work_entry);
		complete(&ctx->priv->parts_work_comp);
	}
out:
	list_for_each_entry_safe(ctx, tmp, &rq->disconn_list, entry)
		if (atomic64_read(&ctx->priv->job_pending_cnt))
			queue_work(rq->work_q, &ctx->dispatch_work);
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
	struct aie2_partition *part;
	struct amdxdna_dev *xdna;
	int active_cnt = 0;
	int stuck_cnt = 0;
	int i;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	for (i = 0; i < rq->num_parts; i++) {
		part = &rq->parts[i];
		if (!part->hwctx_cnt)
			continue;

		active_cnt++;
		if (part_is_all_ctx_stuck(part))
			stuck_cnt++;
	}
	mutex_unlock(&xdna->dev_lock);

	return active_cnt && active_cnt == stuck_cnt;
}

bool aie2_rq_handle_idle_ctx(struct aie2_ctx_rq *rq)
{
	struct aie2_partition *part;
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	int average, remainder;
	int ctx_total = 0;
	bool found = false;
	int i;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	list_for_each_entry(ctx, &rq->disconn_list, entry) {
		if (!ctx->priv->active)
			continue;

		ctx->priv->idle_cnt++;
		if (ctx->priv->idle_cnt == RQ_CTX_IDLE_COUNT) {
			ctx->priv->active = false;
			ctx->priv->idle_cnt = 0;
		}
	}

	for (i = 0; i < rq->num_parts; i++) {
		part = &rq->parts[i];
		ctx_total += part->ctx_cnt;
		if (!part_handle_idle_ctx(part, false))
			continue;

		found = true;
	}

	average = ctx_total / rq->num_parts;
	remainder = ctx_total - (average * rq->num_parts);
	for (i = 0; i < rq->num_parts; i++) {
		int num_move;

		part = &rq->parts[i];
		if (remainder)
			num_move = part->ctx_cnt - (average + 1);
		else
			num_move = part->ctx_cnt - average;
		if (num_move <= 0)
			continue;

		list_for_each_entry(ctx, &part->conn_list, entry) {
			ctx->priv->force_yield = true;
			ctx->priv->status = CTX_STATE_DISCONNECTING;
			ctx->priv->active = false;
			ctx->priv->idle_cnt = 0;
			queue_work(part->rq->work_q, &ctx->yield_work);

			num_move--;
			if (!num_move)
				break;
		}
	}
	mutex_unlock(&xdna->dev_lock);

	return found;
}

void aie2_rq_stop_all(struct aie2_ctx_rq *rq)
{
	struct aie2_partition *part;
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	struct amdxdna_ctx *tmp;
	int i;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	for (i = 0; i < rq->num_parts; i++) {
		part = &rq->parts[i];
		list_for_each_entry_safe(ctx, tmp, &part->conn_list, entry) {
			down_write(&ctx->priv->io_sem);
			XDNA_DBG(xdna, "%s @[%d, %d] stop", ctx->name,
				 part->start_col, part->end_col);
			ctx->priv->should_block = true;
			ctx->priv->force_yield = true;
			part_ctx_stop_wait(ctx, false);
			up_write(&ctx->priv->io_sem);
		}
	}
	mutex_unlock(&xdna->dev_lock);
}

void aie2_rq_restart_all(struct aie2_ctx_rq *rq)
{
	struct aie2_partition *part;
	struct amdxdna_dev *xdna;
	int i;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	if (rq->paused)
		queue_work(rq->work_q, &rq->parts_work);

	for (i = 0; i < rq->num_parts; i++) {
		part = &rq->parts[i];
		queue_work(rq->work_q, &part->sched_work);
	}
	mutex_unlock(&xdna->dev_lock);
}

void aie2_rq_dump_all(struct aie2_ctx_rq *rq)
{
	struct aie2_partition *part;
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	int i;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	for (i = 0; i < rq->num_parts; i++) {
		part = &rq->parts[i];
		list_for_each_entry(ctx, &part->conn_list, entry)
			aie2_dump_ctx(ctx);
	}
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
again:
	queue_work(rq->work_q, &ctx->dispatch_work);
	ret = wait_event_interruptible(ctx->priv->connect_waitq,
				       ctx_is_connected(ctx) || ctx_is_fatal(ctx));
	if (ret) {
		XDNA_DBG(xdna, "%s status %d ret %d", ctx->name,
			 ctx->priv->status, ret);
		goto exit_and_cleanup;
	}

	if (ctx_is_fatal(ctx)) {
		atomic64_dec(&ctx->priv->job_pending_cnt);
		XDNA_ERR(xdna, "%s fatal error", ctx->name);
		return -EIO;
	}

	/*
	 * If a context is on connected list. It will retain connection until
	 * this context call aie2_rq_yield().
	 * At this point, this context will not be swapped out.
	 */
	down_read(&ctx->priv->io_sem);
	if (!ctx_is_connected(ctx)) {
		up_read(&ctx->priv->io_sem);
		goto again;
	}
	atomic64_dec(&ctx->priv->job_pending_cnt);
	return 0;

exit_and_cleanup:
	cancel_work_sync(&ctx->dispatch_work);
	atomic64_dec(&ctx->priv->job_pending_cnt);

	mutex_lock(&xdna->dev_lock);
	if (ctx_is_dispatched(ctx))
		rq_ctx_cancel(rq, ctx);
	if (ctx_is_connected(ctx))
		queue_work(rq->work_q, &ctx->yield_work);
	mutex_unlock(&xdna->dev_lock);
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

static bool
aie2_enable_special_case(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;

	ndev = ctx_rq_to_ndev(rq);
	xdna = ndev->xdna;
	/*
	 * Enable special case support when,
	 * 1. The first column of the device is non-zero.
	 * 2. The columns of context and device are the same.
	 *
	 * After spacial case support is enabled,
	 * 1. Other context doesn't use all columns will fail to create.
	 */
	if (!xdna->dev_info->first_col) {
		XDNA_DBG(xdna, "First column of the device is zero");
		return false;
	}

	if (ctx->priv->orig_num_col != ndev->total_col) {
		XDNA_DBG(xdna, "Context not the same as device total");
		return false;
	}

	if (rq->ctx_cnt) {
		XDNA_DBG(xdna, "Other context is running");
		return false;
	}

	WARN_ON(!rq->start_col);
	rq->start_col_orig = rq->start_col;
	rq->start_col = 0;
	rq->total_cols = ndev->total_col - rq->start_col;
	XDNA_DBG(xdna, "Special case support enabled");

	return true;
}

static void
aie2_disable_special_case(struct aie2_ctx_rq *rq)
{
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;

	ndev = ctx_rq_to_ndev(rq);
	xdna = ndev->xdna;
	if (!rq->start_col_orig)
		return;

	if (rq->ctx_cnt)
		return;

	rq->start_col = rq->start_col_orig;
	rq->total_cols = ndev->total_col - rq->start_col;
	rq->start_col_orig = 0;
	XDNA_DBG(xdna, "Special case support disabled");
}

int aie2_rq_add(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;
	bool wait_parts = false;
	u32 num_col;
	int ret;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	if (rq->ctx_limit == rq->ctx_cnt) {
		XDNA_ERR(xdna, "Not allow more than %d context(s)", rq->ctx_limit);
		ret = -ENOENT;
		goto error;
	}

	if (rq->hwctx_limit == rq->rt_ctx_cnt) {
		XDNA_ERR(xdna, "Not more hwctx");
		ret = -ENOENT;
		goto error;
	}

	if (rq->ctx_cnt > rq->rt_ctx_cnt && ctx_is_rt(ctx) &&
	    rq->rt_ctx_cnt + 1 == rq->hwctx_limit) {
		XDNA_ERR(xdna, "Not more hwctx for RT");
		ret = -ENOENT;
		goto error;
	}

	num_col = ctx->priv->orig_num_col;
	if (rq->start_col_orig && num_col != rq->total_cols) {
		XDNA_ERR(xdna, "Special context is running");
		ret = -EBUSY;
		goto error;
	}

	if (num_col > rq->total_cols) {
		if (!aie2_enable_special_case(rq, ctx)) {
			XDNA_ERR(xdna, "Require %d columns exceed %d",
				 num_col, rq->total_cols);
			ret = -ENOSPC;
			goto error;
		}
	}

	INIT_WORK(&ctx->dispatch_work, rq_dispatch_work);
	INIT_WORK(&ctx->yield_work, rq_yield_work);
	init_completion(&ctx->priv->parts_work_comp);
	ctx->priv->status = CTX_STATE_DISCONNECTED;
	ctx->priv->should_block = false;
	qos_to_rq_prio(ctx);

	rq->ctx_width_resv[num_col]++;
	list_add_tail(&ctx->entry, &rq->disconn_list);
	rq->ctx_cnt++;

	/* Expand partition is needed*/
	if (num_col > rq->max_cols) {
		XDNA_DBG(xdna, "%s request %d colomns, rq max_cols %d",
			 ctx->name, num_col, rq->max_cols);
		wait_parts = true;
	}

	if (ctx_is_rt(ctx)) {
		XDNA_DBG(xdna, "%s is realtime", ctx->name);
		rq->rt_ctx_cnt++;
		wait_parts = true;
	}

	if (wait_parts) {
		list_add_tail(&ctx->parts_work_entry, &rq->parts_work_waitq);
		queue_work(rq->work_q, &rq->parts_work);
	}
	mutex_unlock(&xdna->dev_lock);

	if (wait_update_parts && wait_parts)
		wait_for_completion_killable(&ctx->priv->parts_work_comp);
	XDNA_DBG(xdna, "%s added, status %d priority %d",
		 ctx->name, ctx->priv->status, ctx->priv->priority);
	return 0;

error:
	mutex_unlock(&xdna->dev_lock);
	return ret;
}

void aie2_rq_del(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx)
{
	struct amdxdna_dev *xdna;
	bool wait_parts = false;
	u32 num_col;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	down_write(&ctx->priv->io_sem);
	ctx->priv->should_block = false;
	part_ctx_stop_wait(ctx, true);
	up_write(&ctx->priv->io_sem);

	list_del(&ctx->entry);
	rq->ctx_cnt--;
	if (ctx_is_rt(ctx)) {
		rq->rt_ctx_cnt--;
		wait_parts = true;
	}

	num_col = ctx->priv->orig_num_col;
	rq->ctx_width_resv[num_col]--;
	/* Shrink partition is needed */
	if (!rq->ctx_width_resv[rq->max_cols])
		wait_parts = true;

	aie2_disable_special_case(rq);

	if (wait_parts) {
		list_add_tail(&ctx->parts_work_entry, &rq->parts_work_waitq);
		queue_work(rq->work_q, &rq->parts_work);
	}
	mutex_unlock(&xdna->dev_lock);

	if (wait_update_parts && wait_parts)
		wait_for_completion_killable(&ctx->priv->parts_work_comp);
	flush_work(&ctx->yield_work);
	XDNA_DBG(xdna, "%s deleted, status %d priority %d",
		 ctx->name, ctx->priv->status, ctx->priv->priority);
}

int aie2_rq_init(struct aie2_ctx_rq *rq)
{
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;

	ndev = ctx_rq_to_ndev(rq);
	xdna = ndev->xdna;
	if (context_limit && context_limit != __UINT32_MAX__)
		rq->ctx_limit = context_limit;
	else
		rq->ctx_limit = ndev->priv->ctx_limit;

	if (hwctx_limit && hwctx_limit < ndev->priv->hwctx_limit)
		rq->hwctx_limit = hwctx_limit;
	else
		rq->hwctx_limit = ndev->priv->hwctx_limit;
	XDNA_DBG(xdna, "Maximum limit %d virtual context(s)", rq->ctx_limit);
	XDNA_DBG(xdna, "Maximum limit %d hardware context(s)", rq->hwctx_limit);
	/* Allow user get final values */
	context_limit = rq->ctx_limit;
	hwctx_limit = rq->hwctx_limit;

	if (!rq->ctx_limit || !rq->hwctx_limit) {
		XDNA_ERR(xdna, "Zero context or hwctx limit");
		return -EINVAL;
	}

	rq->start_col = xdna->dev_info->first_col;
#ifdef AMDXDNA_DEVEL
	if (start_col_index >= 0 && start_col_index < ndev->total_col)
		rq->start_col = start_col_index;
#endif
	rq->total_cols = ndev->total_col - rq->start_col;
	XDNA_DBG(xdna, "Columns [%d, %d] total %d",
		 rq->start_col, ndev->total_col - 1, rq->total_cols);

	rq->parts = kcalloc(ndev->total_col, sizeof(*rq->parts), GFP_KERNEL);
	if (!rq->parts)
		return -ENOMEM;

	rq->ctx_width_resv = kcalloc(ndev->total_col + 1, sizeof(*rq->ctx_width_resv), GFP_KERNEL);
	if (!rq->ctx_width_resv)
		goto free_parts;

	/*
	 * For temporal shared only device, hardcoding the all columns counter
	 * to be 1.
	 * 1. There will be only 1 partition to use all available columns.
	 * 2. All contexts will expand and there will be no shrinking.
	 */
	if (ndev->priv->temporal_only) {
		XDNA_DBG(xdna, "Temporal share only device");
		rq->ctx_width_resv[rq->total_cols] = 1;
		rq->max_cols = rq->total_cols;
	}

	rq->work_q = alloc_ordered_workqueue("ctx_runqueue", 0);
	if (!rq->work_q)
		goto free_ctx_width_resv;

	INIT_WORK(&rq->parts_work, rq_parts_work);
	INIT_LIST_HEAD(&rq->parts_work_waitq);
	INIT_LIST_HEAD(&rq->disconn_list);

	rq_part_init(rq);

	return 0;

free_ctx_width_resv:
	kfree(rq->ctx_width_resv);
free_parts:
	kfree(rq->parts);
	return -ENOMEM;
}

void aie2_rq_fini(struct aie2_ctx_rq *rq)
{
	destroy_workqueue(rq->work_q);
	kfree(rq->ctx_width_resv);
	kfree(rq->parts);
}

int aie2_rq_context_limit(struct aie2_ctx_rq *rq)
{
	return rq->ctx_limit;
}

int aie2_rq_active_context(struct aie2_ctx_rq *rq)
{
	return rq->ctx_cnt;
}

#if defined(CONFIG_DEBUG_FS)
int aie2_rq_show(struct aie2_ctx_rq *rq, struct seq_file *m)
{
	struct aie2_partition *part;
	struct amdxdna_dev *xdna;
	struct amdxdna_ctx *ctx;
	int i;

	xdna = ctx_rq_to_xdna_dev(rq);
	mutex_lock(&xdna->dev_lock);
	seq_printf(m, "Start column %d\n", rq->start_col);
	seq_printf(m, "Total columns %d\n", rq->total_cols);

	seq_printf(m, "Number of contexts %d\n", rq->ctx_cnt);
	seq_printf(m, "Number of RT contexts %d\n", rq->rt_ctx_cnt);
	seq_printf(m, "Number of partitions %d\n", rq->num_parts);
	seq_printf(m, "Max cols %d\n", rq->max_cols);

	list_for_each_entry(ctx, &rq->disconn_list, entry) {
		seq_printf(m, "%s status %d pending %lld\n",
			   ctx->name, ctx->priv->status,
			   atomic64_read(&ctx->priv->job_pending_cnt));
	}

	for (i = 0; i < rq->num_parts; i++) {
		part = &rq->parts[i];
		seq_printf(m, "Part [%d, %d]:\n", part->start_col, part->end_col);
		seq_printf(m, "  Max hwctx %d\n", part->max_hwctx);
		seq_printf(m, "  Max RT hwctx %d\n", part->max_rt_ctx);
		seq_printf(m, "  Number of ctx %d\n", part->ctx_cnt);
		seq_printf(m, "  Number of RT ctx %d\n", part->rt_ctx_cnt);
		seq_printf(m, "  Number of hwctx %d\n", part->hwctx_cnt);
	}
	mutex_unlock(&xdna->dev_lock);

	return 0;
}
#endif
