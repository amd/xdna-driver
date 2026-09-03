// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_cache.h>
#include <drm/drm_drv.h>
#include <drm/drm_print.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/pci.h>
#include <linux/rcupdate.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/srcu.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include "aie.h"
#include "amdxdna_dpt.h"
#include "amdxdna_drv.h"

/*
 * Everything that distinguishes one DPT channel from another. The firmware
 * hooks are thunks over aie->msg_ops rather than cached copies of its
 * members, because msg_ops is populated at DPT init while the channels are
 * wired up at probe.
 */
struct amdxdna_dpt_desc {
	const char	*name;
	const char	*irq_name;
	size_t		 buf_size;
	/* Start/stop the firmware producer for this channel. */
	int		(*fw_init)(struct aie_device *aie, size_t size, u32 config);
	int		(*fw_fini)(struct aie_device *aie);
	/*
	 * Render one fetched batch into dmesg, and NULL for a channel whose
	 * payload nothing renders. A NULL @buf is a query rather than a
	 * batch, which is how the dmesg dump gate asks before any payload
	 * exists; either form reports -EOPNOTSUPP when the backend installed
	 * no renderer of its own, so the gate refuses the channel instead of
	 * arming a dump whose batches would be discarded.
	 */
	int		(*parse)(struct aie_device *aie, char *buf, size_t size);
};

static int amdxdna_dpt_log_fw_init(struct aie_device *aie, size_t size, u32 config)
{
	if (!aie->msg_ops.fw_log_init)
		return -EOPNOTSUPP;
	return aie->msg_ops.fw_log_init(aie->xdna, size, config);
}

static int amdxdna_dpt_log_fw_fini(struct aie_device *aie)
{
	if (!aie->msg_ops.fw_log_fini)
		return 0;
	return aie->msg_ops.fw_log_fini(aie->xdna);
}

static int amdxdna_dpt_log_parse(struct aie_device *aie, char *buf, size_t size)
{
	if (!aie->msg_ops.fw_log_parse)
		return -EOPNOTSUPP;
	if (!buf)
		return 0;
	aie->msg_ops.fw_log_parse(aie->xdna, buf, size);
	return 0;
}

static int amdxdna_dpt_trace_fw_init(struct aie_device *aie, size_t size, u32 config)
{
	if (!aie->msg_ops.fw_trace_init)
		return -EOPNOTSUPP;
	return aie->msg_ops.fw_trace_init(aie->xdna, size, config);
}

static int amdxdna_dpt_trace_fw_fini(struct aie_device *aie)
{
	if (!aie->msg_ops.fw_trace_fini)
		return 0;
	return aie->msg_ops.fw_trace_fini(aie->xdna);
}

static const struct amdxdna_dpt_desc amdxdna_dpt_fw_log_desc = {
	.name		= "fw_log",
	.irq_name	= "xdna_fw_log",
	.buf_size	= AMDXDNA_DPT_FW_LOG_SIZE,
	.fw_init	= amdxdna_dpt_log_fw_init,
	.fw_fini	= amdxdna_dpt_log_fw_fini,
	.parse		= amdxdna_dpt_log_parse,
};

static const struct amdxdna_dpt_desc amdxdna_dpt_fw_trace_desc = {
	.name		= "fw_trace",
	.irq_name	= "xdna_fw_trace",
	.buf_size	= AMDXDNA_DPT_FW_TRACE_SIZE,
	.fw_init	= amdxdna_dpt_trace_fw_init,
	.fw_fini	= amdxdna_dpt_trace_fw_fini,
};

const char *amdxdna_dpt_name(const struct amdxdna_dpt *dpt)
{
	return dpt->chan->desc->name;
}

/*
 * Wire up both channels. Called from probe, before any handle can be
 * published, and torn down from the drm release action.
 */
int amdxdna_dpt_chan_init(struct amdxdna_dev *xdna)
{
	int ret;

	xdna->fw_log.desc = &amdxdna_dpt_fw_log_desc;
	xdna->fw_trace.desc = &amdxdna_dpt_fw_trace_desc;
	xdna->fw_log.buf_size = xdna->fw_log.desc->buf_size;
	xdna->fw_trace.buf_size = xdna->fw_trace.desc->buf_size;

	ret = init_srcu_struct(&xdna->fw_log.srcu);
	if (ret)
		return ret;

	ret = init_srcu_struct(&xdna->fw_trace.srcu);
	if (ret) {
		cleanup_srcu_struct(&xdna->fw_log.srcu);
		return ret;
	}

	return 0;
}

void amdxdna_dpt_chan_fini(struct amdxdna_dev *xdna)
{
	cleanup_srcu_struct(&xdna->fw_trace.srcu);
	cleanup_srcu_struct(&xdna->fw_log.srcu);
}

struct amdxdna_dpt *
amdxdna_dpt_enter(struct amdxdna_dpt_chan *chan, int *idx)
{
	struct amdxdna_dpt *dpt;

	*idx = srcu_read_lock(&chan->srcu);
	dpt = srcu_dereference(chan->data, &chan->srcu);
	if (!dpt || READ_ONCE(dpt->status) != AMDXDNA_DPT_ACTIVE) {
		amdxdna_dpt_exit(chan, *idx);
		return NULL;
	}
	return dpt;
}

void amdxdna_dpt_exit(struct amdxdna_dpt_chan *chan, int idx)
{
	srcu_read_unlock(&chan->srcu, idx);
}

/*
 * Wake the watcher when either (a) new log data has been written to
 * the ring (tail has advanced past the caller's last read offset)
 * or (b) the session is no longer ACTIVE so the watcher can return
 * -ESHUTDOWN promptly instead of sleeping forever.
 */
static bool amdxdna_dpt_watch_ready(const struct amdxdna_dpt *dpt, u64 offset)
{
	return READ_ONCE(dpt->status) != AMDXDNA_DPT_ACTIVE ||
	       offset != READ_ONCE(dpt->tail);
}

static int amdxdna_dpt_copy_to_kernel(void *to, const void *from, size_t n)
{
	memcpy(to, from, n);
	return 0;
}

static int amdxdna_dpt_call_parse(struct amdxdna_dpt *dpt, char *buf, size_t size)
{
	const struct amdxdna_dpt_desc *desc = dpt->chan->desc;

	if (!desc->parse)
		return -EOPNOTSUPP;
	return desc->parse(dpt->aie, buf, size);
}

static int amdxdna_dpt_copy_to_user(void *to, const void *from, size_t n)
{
	return copy_to_user((__force void __user *)to, from, n) ? -EFAULT : 0;
}

/*
 * Fetch up to *size bytes from the ring buffer starting at *offset. Returns
 * the actual bytes copied via *size and advances *offset to the new read
 * point.
 */
static int amdxdna_dpt_fetch_payload(struct amdxdna_dpt *dpt, u8 *buf,
				     u64 *offset, u32 *size,
				     int (*cpy)(void *to, const void *from, size_t n))
{
	struct amdxdna_msg_buf_hdl *hdl = dpt->buf;
	size_t req_size, log_size;
	u32 start, end;
	u64 tail;

	log_size = to_buf_size(hdl) - AMDXDNA_DPT_FOOTER_SIZE;

	tail = READ_ONCE(dpt->tail);

	/*
	 * A reader whose offset is ahead of the tail is holding a cursor from
	 * a ring that no longer exists: every publish starts a fresh handle at
	 * tail 0, so an offset saved before a disable/enable cycle can never be
	 * satisfied. -ESTALE tells the consumer to drop that cursor and restart
	 * from offset 0, and unlike a silent reset it also tells it that it
	 * lost its place, so a gap can be recorded rather than a fresh ring
	 * being indistinguishable from missed data. Rate-limit the message: a
	 * consumer that ignores the resync and retries in a loop would
	 * otherwise flood the kernel log.
	 */
	if (tail < *offset) {
		XDNA_DPT_ERR_RATELIMITED(dpt, "Stale fetch offset: 0x%llx",
					 *offset);
		return -ESTALE;
	}

	if (tail == *offset) {
		req_size = 0;
		goto exit;
	}

	/*
	 * When the reader has fallen more than one full ring behind, the
	 * oldest in-ring bytes have already been overwritten. Skip forward to
	 * the start of the still-valid window (tail - log_size) instead of
	 * repeatedly re-reading (and, in the dmesg path, re-logging) the same
	 * beginning-of-ring bytes on every fetch until the cursor catches up.
	 */
	if (tail - *offset > log_size)
		*offset = tail - log_size;

	start = *offset % log_size;
	end = tail % log_size;

	/*
	 * start == end here means the reader is exactly one full ring behind,
	 * so the entire ring is pending (req_size == log_size). It never means
	 * "empty" because the tail == *offset case already returned above.
	 */
	if (end > start)
		req_size = end - start;
	else
		req_size = log_size - start + end;

	if (req_size > *size) {
		XDNA_DPT_DBG(dpt, "Insufficient buffer size: 0x%zx", req_size);
		req_size = *size;
	}

	if (start + req_size > log_size) {
		size_t first = log_size - start;

		/* First chunk: from start to end of log buffer */
		drm_clflush_virt_range(to_cpu_addr(hdl, start), first);
		if (cpy(buf, to_cpu_addr(hdl, start), first))
			return -EFAULT;

		/* Wrap-around chunk: from 0 to the remainder */
		drm_clflush_virt_range(to_cpu_addr(hdl, 0), req_size - first);
		if (cpy(buf + first, to_cpu_addr(hdl, 0), req_size - first))
			return -EFAULT;
	} else {
		drm_clflush_virt_range(to_cpu_addr(hdl, start), req_size);
		if (cpy(buf, to_cpu_addr(hdl, start), req_size))
			return -EFAULT;
	}
exit:
	*size = req_size;
	*offset += req_size;
	return 0;
}

static bool amdxdna_dpt_update_tail(struct amdxdna_dpt *dpt)
{
	struct amdxdna_dpt_footer *footer;
	u32 offset;
	u64 tail;

	offset = to_buf_size(dpt->buf) - AMDXDNA_DPT_FOOTER_SIZE;
	footer = to_cpu_addr(dpt->buf, offset);

	drm_clflush_virt_range(footer, sizeof(*footer));

	/* Extend 32-bit firmware pointer to a 64-bit value to handle wrap. */
	tail = (dpt->tail & ~GENMASK_ULL(31, 0)) | footer->tail;
	if (tail < dpt->tail)
		tail += BIT_ULL(32);

	drm_WARN_ONCE(&dpt->xdna->ddev, tail - dpt->tail > BIT_ULL(31),
		      "Unexpected jump in tail pointer. Missed IRQ or bug");

	if (dpt->tail != tail) {
		WRITE_ONCE(dpt->tail, tail);
		XDNA_DPT_DBG(dpt, "Tail updated: 0x%llx", tail);
		wake_up(&dpt->wait);
		return true;
	}
	return false;
}

static void amdxdna_dpt_read_metadata(struct amdxdna_dpt *dpt)
{
	struct amdxdna_dpt_footer *footer;
	u32 offset;

	offset = to_buf_size(dpt->buf) - AMDXDNA_DPT_FOOTER_SIZE;
	footer = to_cpu_addr(dpt->buf, offset);

	drm_clflush_virt_range(footer, sizeof(*footer));

	dpt->payload_version = footer->payload_version;
	dpt->minor = footer->minor;
	dpt->major = footer->major;

	XDNA_DPT_DBG(dpt, "Version: %d.%d payload: 0x%x",
		     dpt->major, dpt->minor, dpt->payload_version);
}

static irqreturn_t amdxdna_dpt_irq_handler(int irq, void *data)
{
	struct amdxdna_dpt *dpt = data;

	if (dpt->io_base)
		writel(0, dpt->io_base + dpt->msi_address);

	queue_work(system_percpu_wq, &dpt->work);
	return IRQ_HANDLED;
}

static int amdxdna_dpt_irq_init(struct amdxdna_dpt *dpt)
{
	struct amdxdna_dev *xdna = dpt->xdna;
	int ret;

	if (!dpt->msi_idx || !dpt->msi_address)
		return -EINVAL;

	ret = pci_irq_vector(to_pci_dev(xdna->ddev.dev), dpt->msi_idx);
	if (ret < 0) {
		dpt->irq = 0;
		return ret;
	}
	dpt->irq = ret;

	ret = request_irq(dpt->irq, amdxdna_dpt_irq_handler, 0,
			  dpt->chan->desc->irq_name, dpt);
	if (ret) {
		dpt->irq = 0;
		return ret;
	}

	return 0;
}

static void amdxdna_dpt_irq_fini(struct amdxdna_dpt *dpt)
{
	if (dpt->irq) {
		free_irq(dpt->irq, dpt);
		dpt->irq = 0;
	}
	dpt->msi_address = 0;
	dpt->msi_idx = 0;
}

/*
 * Timer refcount. 0 -> 1 starts the polling timer; N -> 0 stops it.
 * timer_lock serializes the transition decisions. The mod_timer arm
 * and inner timer_delete_sync are gated on status == ACTIVE so the
 * suspend path's timer_delete_sync wins exclusively while readers
 * admitted before SUSPENDING continue to balance their refcount.
 */
static void amdxdna_dpt_timer_get(struct amdxdna_dpt *dpt)
{
	mutex_lock(&dpt->timer_lock);
	if (!refcount_read(&dpt->timer_refs)) {
		refcount_set(&dpt->timer_refs, 1);
		if (READ_ONCE(dpt->status) == AMDXDNA_DPT_ACTIVE)
			mod_timer(&dpt->timer,
				  jiffies + msecs_to_jiffies(AMDXDNA_DPT_POLL_INTERVAL_MS));
	} else {
		refcount_inc(&dpt->timer_refs);
	}
	mutex_unlock(&dpt->timer_lock);
}

static void amdxdna_dpt_timer_put(struct amdxdna_dpt *dpt)
{
	mutex_lock(&dpt->timer_lock);
	if (drm_WARN_ON_ONCE(&dpt->xdna->ddev, !refcount_read(&dpt->timer_refs))) {
		mutex_unlock(&dpt->timer_lock);
		return;
	}
	if (refcount_dec_and_test(&dpt->timer_refs) &&
	    READ_ONCE(dpt->status) == AMDXDNA_DPT_ACTIVE)
		timer_delete_sync(&dpt->timer);
	mutex_unlock(&dpt->timer_lock);
}

static void amdxdna_dpt_fetch_and_dump_to_dmesg(struct amdxdna_dpt *dpt)
{
	/*
	 * A single fetch is capped at the local_buffer size and the poll
	 * worker only re-fetches when the tail advances, so drain the whole
	 * backlog up to the current tail here. Otherwise a batch larger than
	 * local_buffer would leave head behind tail and stall until the next
	 * tail advance. Only amdxdna_dpt_update_tail() moves the tail, so it
	 * is a fixed snapshot for the duration of this loop and the loop is
	 * bounded.
	 */
	while (dpt->head != READ_ONCE(dpt->tail)) {
		u32 size = dpt->size;
		int ret;

		ret = amdxdna_dpt_fetch_payload(dpt, dpt->local_buffer, &dpt->head,
						&size, amdxdna_dpt_copy_to_kernel);
		if (ret) {
			XDNA_DPT_ERR_RATELIMITED(dpt, "Failed to fetch FW buffer: %d",
						 ret);
			return;
		}
		if (!size)
			break;

		ret = amdxdna_dpt_call_parse(dpt, dpt->local_buffer, size);
		if (ret) {
			XDNA_DPT_ERR_RATELIMITED(dpt, "Failed to parse FW buffer: %d",
						 ret);
			return;
		}
	}
}

static void amdxdna_dpt_drain_pending_data(struct amdxdna_dpt *dpt)
{
	/*
	 * Refresh the tail from the firmware footer before draining. At enable
	 * time (for example right after resume, before the IRQ or poll worker
	 * has run) the cached tail may lag the ring, so snapshot the latest
	 * first to avoid leaving already-buffered entries until a later worker
	 * run.
	 */
	amdxdna_dpt_update_tail(dpt);
	amdxdna_dpt_fetch_and_dump_to_dmesg(dpt);
}

static void amdxdna_dpt_worker(struct work_struct *w)
{
	struct amdxdna_dpt *dpt = container_of(w, struct amdxdna_dpt, work);

	/*
	 * The worker is the sole consumer of local_buffer / head once
	 * dumping is enabled. Pair the acquire load with the store-release
	 * in amdxdna_dpt_dump_to_dmesg() so that observing dump_to_dmesg
	 * true guarantees local_buffer has been published.
	 */
	if (amdxdna_dpt_update_tail(dpt) && smp_load_acquire(&dpt->dump_to_dmesg))
		amdxdna_dpt_fetch_and_dump_to_dmesg(dpt);
}

int amdxdna_dpt_dump_to_dmesg(struct amdxdna_dpt *dpt, bool enable)
{
	if (!dpt)
		return -EINVAL;

	/*
	 * The poll worker reads dump_to_dmesg with smp_load_acquire() without
	 * taking dev_lock, so use READ_ONCE() here to keep the compare
	 * race-free (a plain read is a data race under KCSAN).
	 */
	if (READ_ONCE(dpt->dump_to_dmesg) == enable)
		return 0;

	if (enable) {
		const struct amdxdna_dpt_desc *desc = dpt->chan->desc;

		/*
		 * dmesg dumping only makes sense when the fetched ring payload
		 * gets rendered, so ask with a query call (a NULL batch) before
		 * committing anything. That reports -EOPNOTSUPP both for a
		 * channel with no parse hook and for one whose backend installed
		 * no renderer, either of which would leave fetched batches
		 * silently discarded, and refusing beats pinning a
		 * multi-megabyte buffer and running the poll worker for nothing.
		 */
		if (!desc->parse || desc->parse(dpt->aie, NULL, 0))
			return -EOPNOTSUPP;

		/*
		 * local_buffer is only a CPU memcpy staging area for the ring
		 * payload (amdxdna_dpt_copy_to_kernel), never a DMA target, so
		 * a virtually contiguous allocation is sufficient and far more
		 * robust than a multi-megabyte physically contiguous kmalloc.
		 */
		dpt->local_buffer = kvzalloc(dpt->size, GFP_KERNEL);
		if (!dpt->local_buffer) {
			XDNA_DPT_ERR(dpt, "Failed to allocate FW fetch buffer");
			return -ENOMEM;
		}
		dpt->head = 0;

		/*
		 * Drain whatever is already in the ring from this (debugfs)
		 * context while dump_to_dmesg is still false, so the worker
		 * skips fetch_and_dump and cannot touch local_buffer / head
		 * concurrently. Only after the initial drain do we publish the
		 * buffer and hand ownership of local_buffer / head to the
		 * worker, which then becomes the sole consumer.
		 */
		amdxdna_dpt_drain_pending_data(dpt);

		/*
		 * Publish local_buffer before dump_to_dmesg becomes visible;
		 * pairs with the acquire load in amdxdna_dpt_worker().
		 */
		smp_store_release(&dpt->dump_to_dmesg, true);
		amdxdna_dpt_timer_get(dpt);
	} else {
		/*
		 * Stop dumping, then quiesce the host pipeline before freeing:
		 * a worker queued by the IRQ handler or poll timer reads
		 * local_buffer, so it must not run past the kvfree. timer_put
		 * may stop the poll timer, and cancel_work_sync waits for any
		 * in-flight worker; a worker requeued afterwards observes
		 * dump_to_dmesg false and skips the dump.
		 */
		WRITE_ONCE(dpt->dump_to_dmesg, false);
		amdxdna_dpt_timer_put(dpt);
		cancel_work_sync(&dpt->work);

		kvfree(dpt->local_buffer);
		dpt->local_buffer = NULL;
		dpt->head = 0;
	}

	return 0;
}

static void amdxdna_dpt_timer(struct timer_list *t)
{
	struct amdxdna_dpt *dpt = container_of(t, struct amdxdna_dpt, timer);

	queue_work(system_percpu_wq, &dpt->work);
	mod_timer(&dpt->timer,
		  jiffies + msecs_to_jiffies(AMDXDNA_DPT_POLL_INTERVAL_MS));
}

/*
 * Tell the firmware to start emitting entries into the @dpt buffer.
 * Returns -EOPNOTSUPP when the backend does not implement this channel
 * so the caller can decide whether that is fatal.
 */
static int amdxdna_dpt_msg_init(struct amdxdna_dpt *dpt)
{
	return dpt->chan->desc->fw_init(dpt->aie, to_buf_size(dpt->buf),
					dpt->config);
}

/*
 * Drain any in-flight reader that briefly observed @dpt in INACTIVE state,
 * unpublish, then free buffer + handle. Used by amdxdna_dpt_publish() when
 * the backend msg_ops init fails after the handle has already been planted.
 */
static void amdxdna_dpt_unpublish(struct amdxdna_dpt *dpt)
{
	struct amdxdna_dpt_chan *chan = dpt->chan;

	rcu_assign_pointer(chan->data, NULL);
	synchronize_srcu(&chan->srcu);

	mutex_destroy(&dpt->timer_lock);
	amdxdna_free_msg_buff(dpt->buf);
	kfree(dpt);
}

/*
 * Allocate a fresh dpt handle, plant it in @chan in INACTIVE state,
 * DMA-alloc its ring buffer, then ask the backend to start emitting
 * via amdxdna_dpt_msg_init. On success the handle is fully active: IRQ has
 * been wired (best-effort), metadata has been read, and status is ACTIVE.
 * On failure the handle has already been unpublished and an ERR_PTR is
 * returned.
 */
static struct amdxdna_dpt *
amdxdna_dpt_publish(struct aie_device *aie, struct amdxdna_dpt_chan *chan,
		    u32 config)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_msg_buf_hdl *hdl;
	struct amdxdna_dpt *dpt;
	int ret;

	if (rcu_access_pointer(chan->data))
		return ERR_PTR(-EBUSY);

	dpt = kzalloc_obj(*dpt);
	if (!dpt)
		return ERR_PTR(-ENOMEM);

	dpt->xdna = xdna;
	dpt->aie = aie;
	dpt->chan = chan;
	dpt->status = AMDXDNA_DPT_INACTIVE;
	dpt->config = config;

	hdl = amdxdna_alloc_msg_buff(xdna, chan->buf_size);
	if (IS_ERR(hdl)) {
		ret = PTR_ERR(hdl);
		XDNA_DPT_ERR(dpt, "Failed to allocate %u byte buffer: %d",
			     chan->buf_size, ret);
		kfree(dpt);
		return ERR_PTR(ret);
	}
	dpt->buf = hdl;
	dpt->size = to_buf_size(hdl);

	memset(to_cpu_addr(hdl, 0), 0, to_buf_size(hdl));
	drm_clflush_virt_range(to_cpu_addr(hdl, 0), to_buf_size(hdl));

	mutex_init(&dpt->timer_lock);
	refcount_set(&dpt->timer_refs, 0);
	init_waitqueue_head(&dpt->wait);
	INIT_WORK(&dpt->work, amdxdna_dpt_worker);
	timer_setup(&dpt->timer, amdxdna_dpt_timer, 0);

	/* Plant the handle in INACTIVE state so the backend's msg_ops init
	 * can reach the DMA buffer + msi-info slots through xdna->fw_*.
	 * Readers see status != ACTIVE in amdxdna_dpt_enter and bail out.
	 */
	rcu_assign_pointer(chan->data, dpt);

	ret = amdxdna_dpt_msg_init(dpt);
	if (ret) {
		amdxdna_dpt_unpublish(dpt);
		return ERR_PTR(ret);
	}

	/*
	 * IRQ is best-effort. On failure, on-demand polling driven by
	 * amdxdna_dpt_timer_get in the watcher and dmesg paths still works.
	 */
	if (amdxdna_dpt_irq_init(dpt))
		XDNA_DPT_WARN(dpt, "IRQ unavailable; tail updates on demand only");

	amdxdna_dpt_read_metadata(dpt);

	WRITE_ONCE(dpt->status, AMDXDNA_DPT_ACTIVE);
	return dpt;
}

/*
 * Watch + fetch path used by amdxdna_get_fw_log. Format matches the
 * firmware ABI so the xrt-smi consumer in shim works unchanged.
 */
static int amdxdna_dpt_get_data(struct amdxdna_dpt *dpt,
				struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dpt_metadata footer = {};
	void __user *buf;
	size_t buf_size;
	int ret = 0;
	u32 offset;

	if (args->num_element != 1)
		return -EINVAL;

	buf_size = args->element_size;
	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, buf_size)) {
		XDNA_DPT_ERR_RATELIMITED(dpt,
					 "Failed to access buffer, element num %d size 0x%x",
					 args->num_element, args->element_size);
		return -EFAULT;
	}

	if (buf_size < sizeof(footer))
		return -ENOSPC;

	offset = buf_size - sizeof(footer);
	if (copy_from_user(&footer, buf + offset, sizeof(footer)))
		return -EFAULT;

	if (XDNA_DPT_MBZ_DBG(dpt, &footer.pad, sizeof(footer.pad)))
		return -EINVAL;

	XDNA_DPT_DBG(dpt, "Requested at offset 0x%llx with watch %s",
		     footer.offset, footer.watch ? "on" : "off");

	if (footer.offset == READ_ONCE(dpt->tail)) {
		if (footer.watch) {
			amdxdna_dpt_timer_get(dpt);
			ret = wait_event_interruptible(dpt->wait,
						       amdxdna_dpt_watch_ready(dpt, footer.offset));
			amdxdna_dpt_timer_put(dpt);

			/*
			 * Woken because we are tearing down or PM-suspending.
			 * SUSPENDING is permitted so admitted watchers can drain
			 * the final batch fetch_payload before status flips to
			 * SUSPENDED.
			 */
			if (READ_ONCE(dpt->status) != AMDXDNA_DPT_ACTIVE &&
			    READ_ONCE(dpt->status) != AMDXDNA_DPT_SUSPENDING) {
				footer.size = 0;
				ret = -ESHUTDOWN;
				goto exit;
			}

			if (ret) {
				XDNA_DPT_DBG(dpt, "Wait interrupted by signal: %d", ret);
				footer.size = 0;
				goto exit;
			}
		} else {
			footer.size = 0;
			goto exit;
		}
	}

	footer.size = offset;
	ret = amdxdna_dpt_fetch_payload(dpt, buf, &footer.offset, &footer.size,
					amdxdna_dpt_copy_to_user);
	if (ret == -ESTALE) {
		/*
		 * Hand back the resync point along with the error. The error
		 * is what tells the consumer its cursor died and that the
		 * data published before the restart is gone; the offset
		 * saves it from having to know that 0 is the only value that
		 * can work. fetch_payload has already reported the condition,
		 * so do not log it a second time.
		 */
		footer.offset = 0;
		footer.size = 0;
	} else if (ret) {
		XDNA_DPT_ERR_RATELIMITED(dpt, "Failed to fetch FW buffer: %d", ret);
		footer.size = 0;
	}

exit:
	/*
	 * -ESHUTDOWN and -ESTALE are reported with metadata, not instead of
	 * it: the first carries a zero-size sentinel, the second the offset
	 * to resume from. A fetch that failed any other way leaves the
	 * caller's buffer untouched, since there is nothing useful to say.
	 */
	if (ret == 0 || ret == -ESHUTDOWN || ret == -ESTALE) {
		if (copy_to_user(buf + offset, &footer, sizeof(footer))) {
			/*
			 * Preserve the original error: the caller needs to
			 * know the channel is gone, or that its cursor is,
			 * more than it needs to know the writeback failed,
			 * and it can tell either way because the metadata it
			 * would have read is unchanged.
			 */
			if (ret == 0)
				ret = -EFAULT;
		}
	}

	XDNA_DPT_DBG(dpt, "Returned size 0x%x offset 0x%llx", footer.size,
		     footer.offset);
	return ret;
}

static int amdxdna_fw_log_init(struct aie_device *aie, u32 level)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt *dpt;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	dpt = amdxdna_dpt_publish(aie, &xdna->fw_log, level);
	if (IS_ERR(dpt)) {
		ret = PTR_ERR(dpt);
		return ret == -EOPNOTSUPP ? 0 : ret;
	}
	return 0;
}

/*
 * Tell the firmware to stop emitting entries into the @dpt buffer.
 * Best-effort: returns the backend error but it is the caller's
 * responsibility to continue tearing the handle down regardless.
 */
static int amdxdna_dpt_msg_fini(struct amdxdna_dpt *dpt)
{
	return dpt->chan->desc->fw_fini(dpt->aie);
}

/*
 * Tear-down path that delivers -ESHUTDOWN to every sleeping watcher,
 * waits for them to exit via synchronize_srcu, and only then frees the
 * handle.
 */
static int amdxdna_dpt_fini_chan(struct aie_device *aie,
				 struct amdxdna_dpt_chan *chan)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt *dpt;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	dpt = rcu_dereference_protected(chan->data,
					lockdep_is_held(&xdna->dev_lock));
	if (!dpt)
		return 0;

	/*
	 * Stop the firmware producer while the RCU slot is still
	 * published so msg_ops fini hooks (e.g. fw_log_fini) can look up
	 * xdna->fw_log / fw_trace. Detach must complete before the buffer
	 * is unmapped below.
	 */
	amdxdna_dpt_msg_fini(dpt);

	/*
	 * Close the publish gate (mirrors amdxdna_dpt_enter's ptr-then-status
	 * read order), then mark in-flight readers to bail. After this no new
	 * srcu_dereference can return this handle, and any reader that
	 * already loaded the pointer will observe SHUTTING_DOWN on its
	 * post-wait status check.
	 */
	rcu_assign_pointer(chan->data, NULL);
	WRITE_ONCE(dpt->status, AMDXDNA_DPT_SHUTTING_DOWN);

	/*
	 * Drain the host-side pipeline (IRQ -> timer -> worker). After
	 * cancel_work_sync no path is left that could call
	 * amdxdna_dpt_update_tail on the detached firmware.
	 */
	amdxdna_dpt_irq_fini(dpt);
	timer_shutdown_sync(&dpt->timer);
	cancel_work_sync(&dpt->work);

	/*
	 * The dmesg consumer (if enabled) held a timer ref and a local
	 * buffer. The timer is already shut down, so release the buffer
	 * directly rather than through amdxdna_dpt_dump_to_dmesg().
	 */
	if (dpt->dump_to_dmesg) {
		dpt->dump_to_dmesg = false;
		kvfree(dpt->local_buffer);
		dpt->local_buffer = NULL;
		dpt->head = 0;
	}

	/*
	 * Release every watcher still parked on this channel. Required for
	 * the steady-state "FW idle, no tail advance" case where
	 * amdxdna_dpt_update_tail's conditional wake_up did not fire;
	 * otherwise the watcher would never observe SHUTTING_DOWN and
	 * synchronize_srcu would deadlock. The flip-before-wake invariant is
	 * preserved: status is already SHUTTING_DOWN here, so any watcher
	 * woken now re-evaluates watch_ready, returns true, and exits with
	 * -ESHUTDOWN.
	 */
	wake_up_all(&dpt->wait);

	/*
	 * Wait for every reader of this channel (including any one we just
	 * woke) to drop the SRCU read lock before freeing the handle. This
	 * uses the channel's own domain, so it is bounded by the wake_up_all
	 * above: a watcher parked on the other channel is neither woken nor
	 * waited for, and cannot stall this teardown.
	 */
	synchronize_srcu(&chan->srcu);

	mutex_destroy(&dpt->timer_lock);
	amdxdna_free_msg_buff(dpt->buf);
	XDNA_DPT_DBG(dpt, "Disabled");
	kfree(dpt);
	return 0;
}

static int amdxdna_dpt_suspend_chan(struct amdxdna_dev *xdna,
				    struct amdxdna_dpt_chan *chan)
{
	struct amdxdna_dpt *dpt;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	dpt = rcu_dereference_protected(chan->data,
					lockdep_is_held(&xdna->dev_lock));
	if (!dpt || READ_ONCE(dpt->status) != AMDXDNA_DPT_ACTIVE)
		return 0;

	/*
	 * Do NOT call the msg_ops fini hook here. On firmware suspend the
	 * firmware persists its ring state (head, tail, seq_number,
	 * write_count) into a reserved region of the host-allocated
	 * buffer's footer; on the next attach with the same buffer it
	 * validates the footer signature and resumes from the saved
	 * offsets. Detaching the buffer (size=0 attach) makes the firmware
	 * start a fresh ring with head = tail = 0 on the next attach,
	 * discarding any saved state.
	 */

	/*
	 * Block new entrants and new mod_timer arms before tearing the
	 * timer down so amdxdna_dpt_timer_get cannot race with us.
	 * Readers admitted before this transition observe SUSPENDING in
	 * the post-wait check and are still allowed to drain the final
	 * batch via fetch_payload.
	 */
	WRITE_ONCE(dpt->status, AMDXDNA_DPT_SUSPENDING);

	amdxdna_dpt_irq_fini(dpt);

	/* timer_delete_sync (not _shutdown_sync) so resume can re-arm. */
	timer_delete_sync(&dpt->timer);
	cancel_work_sync(&dpt->work);

	/*
	 * Capture FW's final tail and wake this channel's sleeping watchers.
	 * They wake under the SRCU read lock with status SUSPENDING, exit
	 * wait_event, and run fetch_payload to copy the final batch to
	 * user space; the channel's own synchronize_srcu below waits for
	 * those reads to finish before we flip status to SUSPENDED, and
	 * ignores readers of the other channel, which this wake_up_all
	 * cannot release.
	 */
	amdxdna_dpt_update_tail(dpt);
	wake_up_all(&dpt->wait);

	synchronize_srcu(&chan->srcu);

	WRITE_ONCE(dpt->status, AMDXDNA_DPT_SUSPENDED);

	XDNA_DPT_DBG(dpt, "Suspended");
	return 0;
}

/*
 * Re-arm a SUSPENDED channel. @fresh selects which side of the firmware
 * contract applies: PM suspend leaves the firmware ring state intact and
 * resumes from the persisted offsets (@fresh false), whereas an FLR
 * wipes only the firmware's in-SRAM state -- the footer cursors survive
 * it and would still be resumed from -- so the ring is restarted from
 * scratch (@fresh true).
 */
static int amdxdna_dpt_resume_chan(struct amdxdna_dev *xdna,
				   struct amdxdna_dpt_chan *chan, bool fresh)
{
	struct amdxdna_dpt *dpt;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	dpt = rcu_dereference_protected(chan->data,
					lockdep_is_held(&xdna->dev_lock));
	if (!dpt || READ_ONCE(dpt->status) != AMDXDNA_DPT_SUSPENDED)
		return 0;

	/*
	 * timer_setup re-init must happen under timer_lock so it cannot
	 * race with a parallel amdxdna_dpt_timer_get observing the
	 * pre-suspend timer state. Status flips to ACTIVE only after
	 * the backend re-arm + IRQ wiring succeeds.
	 */
	mutex_lock(&dpt->timer_lock);
	timer_setup(&dpt->timer, amdxdna_dpt_timer, 0);
	mutex_unlock(&dpt->timer_lock);

	/*
	 * Restart the ring the way amdxdna_dpt_publish() does at enable
	 * time: zero the buffer, which also clears the footer state the
	 * firmware would otherwise resume from (see amdxdna_dpt_suspend_chan),
	 * and drop the host cursors with it. Doing this while the channel is
	 * still SUSPENDED is what makes it safe: no reader can be admitted,
	 * suspend already drained the ones that were, and both the poll
	 * timer and the worker are stopped, so nothing else is looking at
	 * the buffer or at tail / head right now.
	 *
	 * PMFW resets the firmware during an FLR with no driver message, so
	 * the firmware that comes back has no record of the attachment, yet
	 * the cursors it persisted in the footer survive and it resumes
	 * incrementing them. The driver cannot vouch for ring contents
	 * behind an inherited cursor, so a re-attached buffer starts zeroed.
	 */
	if (fresh) {
		memset(to_cpu_addr(dpt->buf, 0), 0, to_buf_size(dpt->buf));
		drm_clflush_virt_range(to_cpu_addr(dpt->buf, 0),
				       to_buf_size(dpt->buf));
		WRITE_ONCE(dpt->tail, 0);
		dpt->head = 0;
	}

	/*
	 * Resubmit the same buffer. The handle is already reachable through
	 * xdna->fw_*, so the backend's init hook can reach it for msi/io_base
	 * storage.
	 */
	ret = amdxdna_dpt_msg_init(dpt);
	if (ret) {
		if (ret != -EOPNOTSUPP)
			XDNA_DPT_ERR(dpt, "Failed to resume: %d", ret);
		return ret;
	}

	if (amdxdna_dpt_irq_init(dpt))
		XDNA_DPT_WARN(dpt, "IRQ unavailable post-resume; polling on demand");

	WRITE_ONCE(dpt->status, AMDXDNA_DPT_ACTIVE);

	/*
	 * Suspend stopped the poll timer with timer_delete_sync but left
	 * timer_refs untouched, so a consumer that held a reference across
	 * suspend (e.g. dmesg dump) can no longer trigger the 0->1 arm in
	 * amdxdna_dpt_timer_get. Re-arm it here under timer_lock now that
	 * the device is ACTIVE again, otherwise polling stays dead and, if
	 * the IRQ is also unavailable, FW-log consumption silently stalls.
	 */
	mutex_lock(&dpt->timer_lock);
	if (refcount_read(&dpt->timer_refs))
		mod_timer(&dpt->timer,
			  jiffies + msecs_to_jiffies(AMDXDNA_DPT_POLL_INTERVAL_MS));
	mutex_unlock(&dpt->timer_lock);

	XDNA_DPT_DBG(dpt, "Resumed");
	return 0;
}

static int amdxdna_fw_log_set_level(struct aie_device *aie, u32 level)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt *dpt;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	dpt = rcu_dereference_protected(xdna->fw_log.data,
					lockdep_is_held(&xdna->dev_lock));
	if (!dpt || READ_ONCE(dpt->status) != AMDXDNA_DPT_ACTIVE)
		return -EINVAL;

	if (!aie->msg_ops.fw_log_config)
		return -EOPNOTSUPP;

	ret = aie->msg_ops.fw_log_config(xdna, level);
	if (ret) {
		XDNA_ERR(xdna, "Failed to change FW log level to %d: %d",
			 level, ret);
		return ret;
	}

	WRITE_ONCE(dpt->config, level);
	XDNA_DBG(xdna, "FW log level changed to %d", level);
	return 0;
}

/*
 * debugfs fw_log_level entry point. Starts logging from INACTIVE, changes
 * the live level while ACTIVE, or stops logging when @level is NONE. Uses
 * the xdna->dpt_aie back-pointer so the common debugfs layer need not know
 * the generation-specific dev_handle layout.
 */
int amdxdna_fw_log_set_state(struct amdxdna_dev *xdna, u32 level)
{
	struct aie_device *aie = xdna->dpt_aie;
	enum amdxdna_dpt_status status;
	struct amdxdna_dpt *dpt;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (level >= AMDXDNA_DPT_FW_LOG_LEVEL_MAX)
		return -EINVAL;
	if (!aie)
		return -ENODEV;

	dpt = rcu_dereference_protected(xdna->fw_log.data,
					lockdep_is_held(&xdna->dev_lock));
	status = dpt ? READ_ONCE(dpt->status) : AMDXDNA_DPT_INACTIVE;

	switch (status) {
	case AMDXDNA_DPT_INACTIVE:
		if (level == AMDXDNA_DPT_FW_LOG_LEVEL_NONE)
			return 0;
		return amdxdna_fw_log_init(aie, level);
	case AMDXDNA_DPT_ACTIVE:
		if (level == AMDXDNA_DPT_FW_LOG_LEVEL_NONE)
			return amdxdna_dpt_fini_chan(aie, &xdna->fw_log);
		return amdxdna_fw_log_set_level(aie, level);
	default:
		XDNA_ERR(xdna, "FW logging not in a stable state, retry");
		return -EBUSY;
	}
}

static int amdxdna_fw_trace_init(struct aie_device *aie, u32 categories)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt *dpt;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	dpt = amdxdna_dpt_publish(aie, &xdna->fw_trace, categories);
	if (IS_ERR(dpt))
		return PTR_ERR(dpt);
	return 0;
}

static int amdxdna_fw_trace_set_categories(struct aie_device *aie, u32 categories)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt *dpt;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	dpt = rcu_dereference_protected(xdna->fw_trace.data,
					lockdep_is_held(&xdna->dev_lock));
	if (!dpt || READ_ONCE(dpt->status) != AMDXDNA_DPT_ACTIVE)
		return -EINVAL;

	if (!aie->msg_ops.fw_trace_config)
		return -EOPNOTSUPP;

	ret = aie->msg_ops.fw_trace_config(xdna, categories);
	if (ret) {
		XDNA_ERR(xdna, "Failed to change FW trace categories to 0x%x: %d",
			 categories, ret);
		return ret;
	}

	WRITE_ONCE(dpt->config, categories);
	XDNA_DBG(xdna, "FW trace categories changed to 0x%x", categories);
	return 0;
}

/*
 * Probe-time entry: auto-starts the log channel only. The trace channel is
 * opt-in via DRM_AMDXDNA_SET_FW_TRACE_STATE to avoid generating large trace
 * payloads unconditionally. Best-effort: per-channel failures surface via
 * XDNA_WARN but the wrapper always returns 0 so callers (per-generation
 * probe paths) cannot abort device bring-up on a logging failure.
 */
int amdxdna_dpt_init(struct aie_device *aie)
{
	int ret;

	/* Record the aie back-pointer so common code (debugfs) can reach
	 * msg_ops without the generation-specific dev_handle layout.
	 */
	aie->xdna->dpt_aie = aie;

	ret = amdxdna_fw_log_init(aie, AMDXDNA_DPT_FW_LOG_LEVEL_DEFAULT);
	if (ret)
		XDNA_WARN(aie->xdna,
			  "Failed to enable FW logging: %d. Retry through debugfs, lowering fw_log_size first if the ring could not be allocated",
			  ret);

	return 0;
}

int amdxdna_dpt_fini(struct aie_device *aie)
{
	int ret;

	/*
	 * Clear the back-pointer before tearing the DPT channels down so a
	 * concurrent or in-flight debugfs handler (amdxdna_fw_log_set_state)
	 * observes a NULL dpt_aie and fails cleanly with -ENODEV instead of
	 * reaching a DPT that teardown is about to free.
	 */
	aie->xdna->dpt_aie = NULL;

	ret = amdxdna_dpt_fini_chan(aie, &aie->xdna->fw_log);
	if (ret)
		return ret;

	return amdxdna_dpt_fini_chan(aie, &aie->xdna->fw_trace);
}

int amdxdna_dpt_suspend(struct amdxdna_dev *xdna)
{
	int ret, ret2;

	/*
	 * The log and trace channels are independent. Suspend both and
	 * aggregate the result so a failure on one does not skip the other;
	 * each channel is a safe no-op when it is not active.
	 */
	ret = amdxdna_dpt_suspend_chan(xdna, &xdna->fw_log);
	ret2 = amdxdna_dpt_suspend_chan(xdna, &xdna->fw_trace);

	return ret ? ret : ret2;
}

int amdxdna_dpt_resume(struct amdxdna_dev *xdna)
{
	int ret, ret2;

	/*
	 * The log and trace channels are independent. Resume both and
	 * aggregate the result so a failure on one does not skip the other;
	 * each channel is a safe no-op when it is not active.
	 */
	ret = amdxdna_dpt_resume_chan(xdna, &xdna->fw_log, false);
	ret2 = amdxdna_dpt_resume_chan(xdna, &xdna->fw_trace, false);

	return ret ? ret : ret2;
}

/*
 * Quiesce both DPT channels for the duration of an FLR.
 *
 * Nothing in the reset path re-issues the per-channel firmware attach
 * (amdxdna_dpt_msg_init), so once the reset firmware comes up it has no
 * record of the rings and stops advancing their tails. A watcher parked
 * in amdxdna_dpt_get_data() is woken only by amdxdna_dpt_update_tail()
 * seeing that tail move, or by a status flip out of ACTIVE, and a reset
 * performs neither: it sleeps until it is killed, pinning a runtime PM
 * reference the whole time.
 *
 * Reuse the PM suspend path, which sends no mailbox traffic and so is
 * safe even when the firmware is already unresponsive. It flips status
 * before waking, so every watcher it releases re-evaluates
 * amdxdna_dpt_watch_ready() and leaves; the synchronize_srcu() inside it
 * waits only for readers its own wake_up_all() can release.
 */
int amdxdna_dpt_reset_prepare(struct amdxdna_dev *xdna)
{
	return amdxdna_dpt_suspend(xdna);
}

/*
 * Bring the DPT channels back after an FLR, restarting each ring rather
 * than resuming it.
 *
 * Callers must invoke this only once the reset has otherwise succeeded.
 * Leaving a channel SUSPENDED is the safe outcome: amdxdna_dpt_enter()
 * rejects that state, so a watcher gets -ESHUTDOWN instead of parking on
 * firmware that is not running, which is the very failure this is meant
 * to prevent. The same holds when the firmware attach itself fails.
 */
int amdxdna_dpt_reset_done(struct amdxdna_dev *xdna)
{
	int ret, ret2;

	ret = amdxdna_dpt_resume_chan(xdna, &xdna->fw_log, true);
	ret2 = amdxdna_dpt_resume_chan(xdna, &xdna->fw_trace, true);

	return ret ? ret : ret2;
}

int amdxdna_get_fw_log(struct aie_device *aie,
		       struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt *dpt;
	int ret, idx;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	dpt = amdxdna_dpt_enter(&xdna->fw_log, &idx);
	if (!dpt)
		return -ESHUTDOWN;

	ret = amdxdna_dpt_get_data(dpt, args);
	amdxdna_dpt_exit(&xdna->fw_log, idx);
	return ret;
}

/*
 * No CAP_SYS_ADMIN check: the (version, status, level) triple is
 * unprivileged-readable so non-root xrt-smi can detect feature
 * presence and current state. The payload (amdxdna_get_fw_log)
 * requires CAP_SYS_ADMIN.
 *
 * Returns -EOPNOTSUPP if the firmware doesn't support this feature.
 * Returns success with status == 0 when the firmware supports it but
 * it is currently disabled.
 */
int amdxdna_get_fw_log_configs(struct aie_device *aie,
			       struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_get_dpt_state config = {};
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt *dpt;
	void __user *buf;
	size_t buf_size;
	int idx;

	if (args->num_element != 1)
		return -EINVAL;

	if (!aie->msg_ops.fw_log_init)
		return -EOPNOTSUPP;

	buf_size = args->element_size;
	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, buf_size)) {
		XDNA_ERR(xdna, "Failed to access buffer, element num %d size 0x%x",
			 args->num_element, args->element_size);
		return -EFAULT;
	}

	if (buf_size < sizeof(config)) {
		XDNA_ERR(xdna, "Insufficient buffer size: 0x%zx", buf_size);
		return -ENOSPC;
	}

	dpt = amdxdna_dpt_enter(&xdna->fw_log, &idx);
	if (dpt) {
		config.version = dpt->payload_version;
		config.status = 1;
		config.config = READ_ONCE(dpt->config);
		amdxdna_dpt_exit(&xdna->fw_log, idx);
	}

	if (copy_to_user(buf, &config, sizeof(config)))
		return -EFAULT;
	return 0;
}

int amdxdna_set_fw_log_state(struct aie_device *aie,
			     struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_set_dpt_state fw_log;
	struct amdxdna_dev *xdna = aie->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!aie->msg_ops.fw_log_init)
		return -EOPNOTSUPP;

	if (args->buffer_size != sizeof(fw_log)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %zu.",
			 args->buffer_size, sizeof(fw_log));
		return -EINVAL;
	}

	if (copy_from_user(&fw_log, u64_to_user_ptr(args->buffer), sizeof(fw_log)))
		return -EFAULT;

	if (XDNA_MBZ_DBG(xdna, &fw_log.pad, sizeof(fw_log.pad)))
		return -EINVAL;

	if (!fw_log.action)
		return amdxdna_dpt_fini_chan(aie, &xdna->fw_log);

	if (!fw_log.config || fw_log.config >= AMDXDNA_DPT_FW_LOG_LEVEL_MAX)
		return -EINVAL;

	if (!rcu_access_pointer(xdna->fw_log.data))
		return amdxdna_fw_log_init(aie, fw_log.config);

	return amdxdna_fw_log_set_level(aie, fw_log.config);
}

int amdxdna_get_fw_trace(struct aie_device *aie,
			 struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt *dpt;
	int ret, idx;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	dpt = amdxdna_dpt_enter(&xdna->fw_trace, &idx);
	if (!dpt)
		return -ESHUTDOWN;

	ret = amdxdna_dpt_get_data(dpt, args);
	amdxdna_dpt_exit(&xdna->fw_trace, idx);
	return ret;
}

/*
 * No CAP_SYS_ADMIN check: the (version, status, categories) triple
 * is unprivileged-readable so non-root xrt-smi can detect feature
 * presence and current state. The payload (amdxdna_get_fw_trace)
 * requires CAP_SYS_ADMIN.
 *
 * Returns -EOPNOTSUPP if the firmware doesn't support this feature.
 * Returns success with status == 0 when the firmware supports it but
 * it is currently disabled.
 */
int amdxdna_get_fw_trace_configs(struct aie_device *aie,
				 struct amdxdna_drm_get_array *args)
{
	struct amdxdna_drm_get_dpt_state config = {};
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt *dpt;
	void __user *buf;
	size_t buf_size;
	int idx;

	if (args->num_element != 1)
		return -EINVAL;

	if (!aie->msg_ops.fw_trace_init)
		return -EOPNOTSUPP;

	buf_size = args->element_size;
	buf = u64_to_user_ptr(args->buffer);
	if (!access_ok(buf, buf_size)) {
		XDNA_ERR(xdna, "Failed to access buffer, element num %d size 0x%x",
			 args->num_element, args->element_size);
		return -EFAULT;
	}

	if (buf_size < sizeof(config)) {
		XDNA_ERR(xdna, "Insufficient buffer size: 0x%zx", buf_size);
		return -ENOSPC;
	}

	dpt = amdxdna_dpt_enter(&xdna->fw_trace, &idx);
	if (dpt) {
		config.version = dpt->payload_version;
		config.status = 1;
		config.config = READ_ONCE(dpt->config);
		amdxdna_dpt_exit(&xdna->fw_trace, idx);
	}

	if (copy_to_user(buf, &config, sizeof(config)))
		return -EFAULT;
	return 0;
}

int amdxdna_set_fw_trace_state(struct aie_device *aie,
			       struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_set_dpt_state fw_trace;
	struct amdxdna_dev *xdna = aie->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!aie->msg_ops.fw_trace_init)
		return -EOPNOTSUPP;

	if (args->buffer_size != sizeof(fw_trace)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %zu.",
			 args->buffer_size, sizeof(fw_trace));
		return -EINVAL;
	}

	if (copy_from_user(&fw_trace, u64_to_user_ptr(args->buffer),
			   sizeof(fw_trace)))
		return -EFAULT;

	if (XDNA_MBZ_DBG(xdna, &fw_trace.pad, sizeof(fw_trace.pad)))
		return -EINVAL;

	if (!fw_trace.action)
		return amdxdna_dpt_fini_chan(aie, &xdna->fw_trace);

	if (!fw_trace.config)
		return -EINVAL;

	if (!rcu_access_pointer(xdna->fw_trace.data))
		return amdxdna_fw_trace_init(aie, fw_trace.config);

	return amdxdna_fw_trace_set_categories(aie, fw_trace.config);
}
