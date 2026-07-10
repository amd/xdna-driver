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
#include "amdxdna_pci_drv.h"

const char * const amdxdna_dpt_irq_name[AMDXDNA_DPT_KIND_MAX] = {
	[AMDXDNA_DPT_FW_LOG]   = "xdna_fw_log",
	[AMDXDNA_DPT_FW_TRACE] = "xdna_fw_trace",
};

const char *amdxdna_dpt_kind_str(enum amdxdna_dpt_kind kind)
{
	static const char * const names[AMDXDNA_DPT_KIND_MAX] = {
		[AMDXDNA_DPT_FW_LOG]   = "fw_log",
		[AMDXDNA_DPT_FW_TRACE] = "fw_trace",
	};

	return (kind < AMDXDNA_DPT_KIND_MAX) ? names[kind] : "fw_???";
}

int fw_log_level_check(u32 level)
{
	if (!level || level >= AMDXDNA_DPT_FW_LOG_LEVEL_MAX)
		return -ERANGE;

	return 0;
}

static struct amdxdna_dpt __rcu **
amdxdna_dpt_slot(struct amdxdna_dev *xdna, enum amdxdna_dpt_kind kind)
{
	switch (kind) {
	case AMDXDNA_DPT_FW_LOG:
		return &xdna->fw_log;
	case AMDXDNA_DPT_FW_TRACE:
		return &xdna->fw_trace;
	case AMDXDNA_DPT_KIND_MAX:
		break;
	}
	return NULL;
}

static struct amdxdna_dpt *
amdxdna_dpt_enter_kind(struct amdxdna_dev *xdna, enum amdxdna_dpt_kind kind,
		       int *idx)
{
	struct amdxdna_dpt __rcu **slot;
	struct amdxdna_dpt *dpt;

	slot = amdxdna_dpt_slot(xdna, kind);
	if (!slot)
		return NULL;

	*idx = srcu_read_lock(&xdna->dpt_srcu);
	dpt = srcu_dereference(*slot, &xdna->dpt_srcu);
	if (!dpt || READ_ONCE(dpt->status) != AMDXDNA_DPT_ACTIVE) {
		srcu_read_unlock(&xdna->dpt_srcu, *idx);
		return NULL;
	}
	return dpt;
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

	if (tail < *offset) {
		XDNA_DPT_ERR(dpt, "Invalid fetch offset: 0x%llx", *offset);
		return -EINVAL;
	}

	if (tail == *offset) {
		req_size = 0;
		goto exit;
	}

	start = *offset % log_size;
	end = tail % log_size;

	/*
	 * When the firmware has wrapped past our slot by more than one full
	 * buffer, re-anchor at the start of the buffer to deliver the most
	 * recent entries.
	 */
	if (tail - *offset >= log_size + start)
		start = 0;

	if (end > start) {
		req_size = end - start;
		if (req_size > *size) {
			XDNA_DPT_DBG(dpt, "Insufficient buffer size: 0x%zx", req_size);
			end = start + *size;
			req_size = *size;
		}
	} else {
		req_size = log_size - start + end;
		if (req_size > *size) {
			XDNA_DPT_DBG(dpt, "Insufficient buffer size: 0x%zx", req_size);
			if (start + *size <= log_size)
				end = start + *size;
			else
				end = *size - (log_size - start);
			req_size = *size;
		}
	}

	if (start > end) {
		/* First chunk: from start to end of log buffer */
		drm_clflush_virt_range(to_cpu_addr(hdl, start), log_size - start);
		if (cpy(buf, to_cpu_addr(hdl, start), log_size - start))
			return -EFAULT;

		/* Wrap-around chunk: from 0 to end */
		drm_clflush_virt_range(to_cpu_addr(hdl, 0), end);
		if (cpy(buf + (log_size - start), to_cpu_addr(hdl, 0), end))
			return -EFAULT;
	} else {
		drm_clflush_virt_range(to_cpu_addr(hdl, start), end - start);
		if (cpy(buf, to_cpu_addr(hdl, start), end - start))
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

	queue_work(system_wq, &dpt->work);
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
			  amdxdna_dpt_irq_name[dpt->kind], dpt);
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
	if (WARN_ON(!refcount_read(&dpt->timer_refs))) {
		mutex_unlock(&dpt->timer_lock);
		return;
	}
	if (refcount_dec_and_test(&dpt->timer_refs) &&
	    READ_ONCE(dpt->status) == AMDXDNA_DPT_ACTIVE)
		timer_delete_sync(&dpt->timer);
	mutex_unlock(&dpt->timer_lock);
}

static void amdxdna_dpt_worker(struct work_struct *w)
{
	struct amdxdna_dpt *dpt = container_of(w, struct amdxdna_dpt, work);

	amdxdna_dpt_update_tail(dpt);
}

static void amdxdna_dpt_timer(struct timer_list *t)
{
	struct amdxdna_dpt *dpt = container_of(t, struct amdxdna_dpt, timer);

	queue_work(system_wq, &dpt->work);
	mod_timer(&dpt->timer,
		  jiffies + msecs_to_jiffies(AMDXDNA_DPT_POLL_INTERVAL_MS));
}

/*
 * Tell the firmware to start emitting entries into the @dpt buffer
 * for the consumer of @dpt->kind. Returns -EOPNOTSUPP when the backend
 * does not implement this kind so the caller can decide whether that is
 * fatal.
 */
static int amdxdna_dpt_msg_init(struct amdxdna_dpt *dpt)
{
	struct aie_device *aie = dpt->aie;

	switch (dpt->kind) {
	case AMDXDNA_DPT_FW_LOG:
		if (!aie->msg_ops.fw_log_init)
			return -EOPNOTSUPP;
		return aie->msg_ops.fw_log_init(dpt->xdna,
						to_buf_size(dpt->buf),
						dpt->config);
	case AMDXDNA_DPT_FW_TRACE:
		if (!aie->msg_ops.fw_trace_init)
			return -EOPNOTSUPP;
		return aie->msg_ops.fw_trace_init(dpt->xdna,
						  to_buf_size(dpt->buf),
						  dpt->config);
	case AMDXDNA_DPT_KIND_MAX:
		break;
	}
	return -EINVAL;
}

/*
 * Drain any in-flight reader that briefly observed @dpt in INACTIVE state,
 * unpublish, then free buffer + handle. Used by amdxdna_dpt_publish() when
 * the backend msg_ops init fails after the handle has already been planted.
 */
static void amdxdna_dpt_unpublish(struct amdxdna_dpt *dpt)
{
	struct amdxdna_dev *xdna = dpt->xdna;
	struct amdxdna_dpt __rcu **slot;

	slot = amdxdna_dpt_slot(xdna, dpt->kind);
	if (slot)
		rcu_assign_pointer(*slot, NULL);
	synchronize_srcu(&xdna->dpt_srcu);

	mutex_destroy(&dpt->timer_lock);
	amdxdna_free_msg_buff(dpt->buf);
	kfree(dpt);
}

/*
 * Allocate a fresh dpt handle, plant it in the slot for @kind in INACTIVE
 * state, DMA-alloc its ring buffer, then ask the backend to start emitting
 * via amdxdna_dpt_msg_init. On success the handle is fully active: IRQ has
 * been wired (best-effort), metadata has been read, and status is ACTIVE.
 * On failure the handle has already been unpublished and an ERR_PTR is
 * returned.
 */
static struct amdxdna_dpt *
amdxdna_dpt_publish(struct aie_device *aie, enum amdxdna_dpt_kind kind,
		    size_t buf_size, u32 config)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_msg_buf_hdl *hdl;
	struct amdxdna_dpt __rcu **slot;
	struct amdxdna_dpt *dpt;
	int ret;

	slot = amdxdna_dpt_slot(xdna, kind);
	if (!slot)
		return ERR_PTR(-EINVAL);

	if (rcu_access_pointer(*slot))
		return ERR_PTR(-EBUSY);

	dpt = kzalloc_obj(*dpt);
	if (!dpt)
		return ERR_PTR(-ENOMEM);

	dpt->xdna = xdna;
	dpt->aie = aie;
	dpt->kind = kind;
	dpt->status = AMDXDNA_DPT_INACTIVE;
	dpt->config = config;

	hdl = amdxdna_alloc_msg_buff(xdna, buf_size);
	if (IS_ERR(hdl)) {
		ret = PTR_ERR(hdl);
		XDNA_DPT_ERR(dpt, "Failed to allocate buffer: %d", ret);
		kfree(dpt);
		return ERR_PTR(ret);
	}
	dpt->buf = hdl;

	memset(to_cpu_addr(hdl, 0), 0, to_buf_size(hdl));
	drm_clflush_virt_range(to_cpu_addr(hdl, 0), to_buf_size(hdl));

	mutex_init(&dpt->timer_lock);
	refcount_set(&dpt->timer_refs, 0);
	init_waitqueue_head(&dpt->wait);
	INIT_WORK(&dpt->work, amdxdna_dpt_worker);
	timer_setup(&dpt->timer, amdxdna_dpt_timer, 0);

	/* Plant the handle in INACTIVE state so the backend's msg_ops init
	 * can reach the DMA buffer + msi-info slots through xdna->fw_*.
	 * Readers see status != ACTIVE in amdxdna_dpt_enter_kind and bail out.
	 */
	rcu_assign_pointer(*slot, dpt);

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
		XDNA_DPT_ERR(dpt, "Failed to access buffer, element num %d size 0x%x",
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
	if (ret) {
		XDNA_DPT_ERR(dpt, "Failed to fetch FW buffer: %d", ret);
		footer.offset = 0;
		footer.size = 0;
		ret = -EINVAL;
	}

exit:
	if (ret == 0 || ret == -ESHUTDOWN) {
		if (copy_to_user(buf + offset, &footer, sizeof(footer))) {
			/*
			 * On -ESHUTDOWN preserve the original error: user
			 * space still gets the zero-size sentinel via the
			 * footer.size = 0 already set on the shutdown
			 * branch above, and even if the writeback fails
			 * the disabled-kind status code must reach the
			 * caller intact.
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

	dpt = amdxdna_dpt_publish(aie, AMDXDNA_DPT_FW_LOG,
				  AMDXDNA_DPT_FW_LOG_SIZE, level);
	if (IS_ERR(dpt)) {
		ret = PTR_ERR(dpt);
		return ret == -EOPNOTSUPP ? 0 : ret;
	}
	return 0;
}

/*
 * Tell the firmware to stop emitting entries into the @dpt buffer
 * for the consumer of @dpt->kind. Best-effort: returns the backend
 * error but it is the caller's responsibility to continue tearing the
 * handle down regardless.
 */
static int amdxdna_dpt_msg_fini(struct amdxdna_dpt *dpt)
{
	struct aie_device *aie = dpt->aie;

	switch (dpt->kind) {
	case AMDXDNA_DPT_FW_LOG:
		if (aie->msg_ops.fw_log_fini)
			return aie->msg_ops.fw_log_fini(dpt->xdna);
		return 0;
	case AMDXDNA_DPT_FW_TRACE:
		if (aie->msg_ops.fw_trace_fini)
			return aie->msg_ops.fw_trace_fini(dpt->xdna);
		return 0;
	case AMDXDNA_DPT_KIND_MAX:
		break;
	}
	return -EINVAL;
}

/*
 * Tear-down path that delivers -ESHUTDOWN to every sleeping watcher,
 * waits for them to exit via synchronize_srcu, and only then frees the
 * handle.
 */
static int amdxdna_dpt_fini_kind(struct aie_device *aie, enum amdxdna_dpt_kind kind)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt __rcu **slot;
	struct amdxdna_dpt *dpt;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	slot = amdxdna_dpt_slot(xdna, kind);
	if (!slot)
		return -EINVAL;

	dpt = rcu_dereference_protected(*slot,
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
	 * Close the publish gate (mirrors enter_kind's ptr-then-status read
	 * order), then mark in-flight readers to bail. After this no new
	 * srcu_dereference can return this handle, and any reader that
	 * already loaded the pointer will observe SHUTTING_DOWN on its
	 * post-wait status check.
	 */
	rcu_assign_pointer(*slot, NULL);
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
	 * Release any watcher still parked. Required for the steady-state
	 * "FW idle, no tail advance" case where amdxdna_dpt_update_tail's
	 * conditional wake_up did not fire; otherwise the watcher would
	 * never observe SHUTTING_DOWN and synchronize_srcu would deadlock.
	 * The flip-before-wake invariant is preserved: status is already
	 * SHUTTING_DOWN here, so any watcher woken now re-evaluates
	 * watch_ready, returns true, and exits with -ESHUTDOWN.
	 */
	wake_up_all(&dpt->wait);

	/*
	 * Wait for every reader currently inside a dpt_* helper
	 * (including any one we just woke) to drop the SRCU read lock
	 * before freeing the handle.
	 */
	synchronize_srcu(&xdna->dpt_srcu);

	mutex_destroy(&dpt->timer_lock);
	amdxdna_free_msg_buff(dpt->buf);
	XDNA_DPT_DBG(dpt, "Disabled");
	kfree(dpt);
	return 0;
}

static int amdxdna_dpt_suspend_kind(struct aie_device *aie,
				    enum amdxdna_dpt_kind kind)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt __rcu **slot;
	struct amdxdna_dpt *dpt;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	slot = amdxdna_dpt_slot(xdna, kind);
	if (!slot)
		return -EINVAL;

	dpt = rcu_dereference_protected(*slot,
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
	 * Capture FW's final tail and wake sleeping watchers. They wake
	 * under the SRCU read lock with status SUSPENDING, exit
	 * wait_event, and run fetch_payload to copy the final batch to
	 * user space; synchronize_srcu below waits for those reads to
	 * finish before we flip status to SUSPENDED.
	 */
	amdxdna_dpt_update_tail(dpt);
	wake_up_all(&dpt->wait);

	synchronize_srcu(&xdna->dpt_srcu);

	WRITE_ONCE(dpt->status, AMDXDNA_DPT_SUSPENDED);

	XDNA_DPT_DBG(dpt, "Suspended");
	return 0;
}

static int amdxdna_dpt_resume_kind(struct aie_device *aie,
				   enum amdxdna_dpt_kind kind)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt __rcu **slot;
	struct amdxdna_dpt *dpt;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	slot = amdxdna_dpt_slot(xdna, kind);
	if (!slot)
		return -EINVAL;

	dpt = rcu_dereference_protected(*slot,
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
	 * Resubmit the same buffer without clearing it. The handle is
	 * already reachable through xdna->fw_*, so the backend's init
	 * hook can reach it for msi/io_base storage.
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

	XDNA_DPT_DBG(dpt, "Resumed");
	return 0;
}

static int amdxdna_fw_log_set_level(struct aie_device *aie, u32 level)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt *dpt;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	dpt = rcu_dereference_protected(xdna->fw_log,
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

static int amdxdna_fw_trace_init(struct aie_device *aie, u32 categories)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt *dpt;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	dpt = amdxdna_dpt_publish(aie, AMDXDNA_DPT_FW_TRACE,
				  AMDXDNA_DPT_FW_TRACE_SIZE, categories);
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

	dpt = rcu_dereference_protected(xdna->fw_trace,
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
 * Probe-time entry: auto-starts FW_LOG only. FW_TRACE is opt-in via
 * DRM_AMDXDNA_SET_FW_TRACE_STATE to avoid generating large trace payloads
 * unconditionally. Best-effort: per-kind failures surface via XDNA_WARN
 * but the wrapper always returns 0 so callers (per-generation probe paths)
 * cannot abort device bring-up on a logging failure.
 */
int amdxdna_dpt_init(struct aie_device *aie)
{
	int ret;

	ret = amdxdna_fw_log_init(aie, AMDXDNA_DPT_FW_LOG_LEVEL_DEFAULT);
	if (ret)
		XDNA_WARN(aie->xdna, "Failed to enable FW logging: %d", ret);

	return 0;
}

int amdxdna_dpt_fini(struct aie_device *aie)
{
	int ret;

	ret = amdxdna_dpt_fini_kind(aie, AMDXDNA_DPT_FW_LOG);
	if (ret)
		return ret;

	return amdxdna_dpt_fini_kind(aie, AMDXDNA_DPT_FW_TRACE);
}

int amdxdna_dpt_suspend(struct aie_device *aie)
{
	int ret;

	ret = amdxdna_dpt_suspend_kind(aie, AMDXDNA_DPT_FW_LOG);
	if (ret)
		return ret;

	return amdxdna_dpt_suspend_kind(aie, AMDXDNA_DPT_FW_TRACE);
}

int amdxdna_dpt_resume(struct aie_device *aie)
{
	int ret;

	ret = amdxdna_dpt_resume_kind(aie, AMDXDNA_DPT_FW_LOG);
	if (ret)
		return ret;

	return amdxdna_dpt_resume_kind(aie, AMDXDNA_DPT_FW_TRACE);
}

int amdxdna_get_fw_log(struct aie_device *aie,
		       struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_dpt *dpt;
	int ret, idx;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	dpt = amdxdna_dpt_enter_kind(xdna, AMDXDNA_DPT_FW_LOG, &idx);
	if (!dpt)
		return -ESHUTDOWN;

	ret = amdxdna_dpt_get_data(dpt, args);
	srcu_read_unlock(&xdna->dpt_srcu, idx);
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

	dpt = amdxdna_dpt_enter_kind(xdna, AMDXDNA_DPT_FW_LOG, &idx);
	if (dpt) {
		config.version = dpt->payload_version;
		config.status = 1;
		config.config = READ_ONCE(dpt->config);
		srcu_read_unlock(&xdna->dpt_srcu, idx);
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
		return amdxdna_dpt_fini_kind(aie, AMDXDNA_DPT_FW_LOG);

	if (fw_log_level_check(fw_log.config))
		return -ERANGE;

	if (!rcu_access_pointer(xdna->fw_log))
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

	dpt = amdxdna_dpt_enter_kind(xdna, AMDXDNA_DPT_FW_TRACE, &idx);
	if (!dpt)
		return -ESHUTDOWN;

	ret = amdxdna_dpt_get_data(dpt, args);
	srcu_read_unlock(&xdna->dpt_srcu, idx);
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

	dpt = amdxdna_dpt_enter_kind(xdna, AMDXDNA_DPT_FW_TRACE, &idx);
	if (dpt) {
		config.version = dpt->payload_version;
		config.status = 1;
		config.config = READ_ONCE(dpt->config);
		srcu_read_unlock(&xdna->dpt_srcu, idx);
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
		return amdxdna_dpt_fini_kind(aie, AMDXDNA_DPT_FW_TRACE);

	if (!fw_trace.config)
		return -EINVAL;

	if (!rcu_access_pointer(xdna->fw_trace))
		return amdxdna_fw_trace_init(aie, fw_trace.config);

	return amdxdna_fw_trace_set_categories(aie, fw_trace.config);
}
