// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2026, Advanced Micro Devices, Inc.
 */

#include <drm/drm_cache.h>
#include <drm/drm_device.h>
#include <drm/drm_print.h>
#include <linux/bits.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include "aie.h"
#include "amdxdna_error.h"
#include "amdxdna_drv.h"

/*
 * The AIE tile error report payload layout below is defined by the AIE device
 * and is common to the aie2 and aie4 firmware. The categorization of an
 * event_id (which category / driver error number it maps to) is specific to the
 * AIE generation, so it is NOT here: each back end supplies its own tables via
 * struct aie_async_error_desc.luts.
 */

/* Do not pack, unless the AIE side changes */
struct aie_error {
	__u8			row;
	__u8			col;
	__u32			mod_type;
	__u8			event_id;
};

struct aie_err_info {
	u32			err_cnt;
	u32			ret_code;
	u32			rsvd;
	struct aie_error	payload[] __counted_by(err_cnt);
};

/* Mailbox async response header. status and type are at fixed offsets. */
struct amdxdna_async_event_resp {
	u32			status;
	u32			type;
};

/**
 * struct amdxdna_async_event - one async error report buffer slot
 * @aie: back pointer to the shared aie device.
 * @events: owning event pool.
 * @work: worker that decodes the report and re-registers the slot.
 * @hdl: message buffer backing this slot.
 * @buf: CPU address of the report buffer.
 * @addr: DMA address of the report buffer.
 * @size: report buffer size.
 * @resp: last mailbox response (status and event type) for this slot.
 */
struct amdxdna_async_event {
	struct aie_device		*aie;
	struct amdxdna_async_events	*events;
	struct work_struct		work;
	struct amdxdna_msg_buf_hdl	*hdl;
	void				*buf;
	dma_addr_t			addr;
	u32				size;
	struct amdxdna_async_event_resp	resp;
};

/**
 * struct amdxdna_async_events - pool of async error report buffer slots
 * @wq: ordered workqueue that runs the report and notification workers.
 * @scratch: ASYNC_BUF_SIZE buffer the report worker decodes from; NULL in a
 *           pool without slots.
 * @armed: set from init() until fini(); gates the re-arm in the report
 *         worker. Written and read under dev_lock.
 * @slot_cnt: number of slots that hold a report buffer: fewer than requested
 *            if allocation fell short, zero for a pool that only carries
 *            firmware notifications.
 * @event: event slots, each with its own message buffer.
 *
 * The pool lives from probe to remove, and its slots are armed with firmware
 * only between hw start and hw stop. A resume therefore never allocates, and a
 * mailbox message that still references a slot never points at freed memory.
 * One scratch buffer is enough because @wq never runs two workers at once.
 */
struct amdxdna_async_events {
	struct workqueue_struct		*wq;
	void				*scratch;
	bool				armed;
	u32				slot_cnt;
	struct amdxdna_async_event	event[] __counted_by(slot_cnt);
};

/*
 * The category to driver-error-number and module to driver-error-module maps,
 * and the human-readable strings, are arch-independent. Only the per-arch event
 * tables (which produce the category and event name) differ.
 */
static const enum amdxdna_error_num aie_cat_err_num_map[] = {
	[AIE_ERROR_SATURATION] = AMDXDNA_ERROR_NUM_AIE_SATURATION,
	[AIE_ERROR_FP] = AMDXDNA_ERROR_NUM_AIE_FP,
	[AIE_ERROR_STREAM] = AMDXDNA_ERROR_NUM_AIE_STREAM,
	[AIE_ERROR_ACCESS] = AMDXDNA_ERROR_NUM_AIE_ACCESS,
	[AIE_ERROR_BUS] = AMDXDNA_ERROR_NUM_AIE_BUS,
	[AIE_ERROR_INSTRUCTION] = AMDXDNA_ERROR_NUM_AIE_INSTRUCTION,
	[AIE_ERROR_ECC] = AMDXDNA_ERROR_NUM_AIE_ECC,
	[AIE_ERROR_LOCK] = AMDXDNA_ERROR_NUM_AIE_LOCK,
	[AIE_ERROR_DMA] = AMDXDNA_ERROR_NUM_AIE_DMA,
	[AIE_ERROR_MEM_PARITY] = AMDXDNA_ERROR_NUM_AIE_MEM_PARITY,
	[AIE_ERROR_UNKNOWN] = AMDXDNA_ERROR_NUM_UNKNOWN,
};

static_assert(ARRAY_SIZE(aie_cat_err_num_map) == AIE_ERROR_UNKNOWN + 1);

static const enum amdxdna_error_module aie_err_mod_map[] = {
	[AIE_MEM_MOD] = AMDXDNA_ERROR_MODULE_AIE_MEMORY,
	[AIE_CORE_MOD] = AMDXDNA_ERROR_MODULE_AIE_CORE,
	[AIE_PL_MOD] = AMDXDNA_ERROR_MODULE_AIE_PL,
	[AIE_UNKNOWN_MOD] = AMDXDNA_ERROR_MODULE_UNKNOWN,
};

static_assert(ARRAY_SIZE(aie_err_mod_map) == AIE_UNKNOWN_MOD + 1);

static const char * const aie_module_names[] = {
	[AIE_MEM_MOD] = "Memory",
	[AIE_CORE_MOD] = "Core",
	[AIE_PL_MOD] = "Shim",
	[AIE_UNKNOWN_MOD] = "Unknown",
};

static_assert(ARRAY_SIZE(aie_module_names) == AIE_UNKNOWN_MOD + 1);

static const char * const aie_category_names[] = {
	[AIE_ERROR_SATURATION] = "Saturation",
	[AIE_ERROR_FP] = "FP",
	[AIE_ERROR_STREAM] = "Stream",
	[AIE_ERROR_ACCESS] = "Access",
	[AIE_ERROR_BUS] = "Bus",
	[AIE_ERROR_INSTRUCTION] = "Instruction",
	[AIE_ERROR_ECC] = "ECC",
	[AIE_ERROR_LOCK] = "Lock",
	[AIE_ERROR_DMA] = "DMA",
	[AIE_ERROR_MEM_PARITY] = "Mem parity",
	[AIE_ERROR_UNKNOWN] = "Unknown",
};

static_assert(ARRAY_SIZE(aie_category_names) == AIE_ERROR_UNKNOWN + 1);

void amdxdna_aie_fill_decode(enum aie_error_category cat, u32 mod_type,
			     const char *event_name,
			     struct amdxdna_aie_err_decode *out)
{
	enum aie_module_type mod;

	mod = (mod_type >= AIE_UNKNOWN_MOD) ? AIE_UNKNOWN_MOD : mod_type;
	if (cat > AIE_ERROR_UNKNOWN)
		cat = AIE_ERROR_UNKNOWN;

	out->err_num = aie_cat_err_num_map[cat];
	out->err_mod = aie_err_mod_map[mod];
	out->mod_str = aie_module_names[mod];
	out->cat_str = aie_category_names[cat];
	out->event_str = event_name ? event_name : "unknown";
}

/*
 * A row hosts a dedicated mem tile when it falls within the firmware-reported
 * mem-tile row range [mem.row_start, mem.row_start + mem.row_count). This
 * replaces the aie2 hard-coded "row == 1" test: on documented aie2 layouts
 * the single mem tile sits at row 1, so the metadata range is {1, 1} and the
 * aie2 decode is unchanged, while other generations use their reported range.
 */
static bool aie_row_is_mem_tile(const struct aie_device *aie, u8 row)
{
	return row >= aie->metadata.mem.row_start &&
	       row <  aie->metadata.mem.row_start + aie->metadata.mem.row_count;
}

enum aie_error_category
aie_lookup_error_category(struct aie_device *aie,
			  u8 row, u8 event_id, u32 mod_type, const char **name)
{
	const struct aie_error_lut_set *set = &aie->xdna->dev_info->async_error->luts;
	const struct aie_error_event *tbl;
	const struct aie_error_event *e;

	*name = "unknown";

	switch (mod_type) {
	case AIE_PL_MOD:
		tbl = set->shim;
		break;
	case AIE_CORE_MOD:
		tbl = set->core;
		break;
	case AIE_MEM_MOD:
		tbl = aie_row_is_mem_tile(aie, row) ? set->mem_tile : set->mem;
		break;
	default:
		return AIE_ERROR_UNKNOWN;
	}

	/* Tables are terminated by a sentinel entry with a NULL name. */
	for (e = tbl; e->name; e++) {
		if (e->event_id != event_id)
			continue;

		*name = e->name;
		return e->category > AIE_ERROR_UNKNOWN ? AIE_ERROR_UNKNOWN : e->category;
	}

	return AIE_ERROR_UNKNOWN;
}

/*
 * Decode one AIE tile error into @d using the arch's category tables
 * (async_error->luts) for the category and event name, then the shared
 * num/module/string mapping.
 */
static void amdxdna_aie_decode_one(struct aie_device *aie,
				   u8 row, u8 event_id, u32 mod_type,
				   struct amdxdna_aie_err_decode *d)
{
	enum aie_error_category cat = AIE_ERROR_UNKNOWN;
	const char *name = "unknown";

	if (mod_type < AIE_UNKNOWN_MOD)
		cat = aie_lookup_error_category(aie, row, event_id, mod_type, &name);

	amdxdna_aie_fill_decode(cat, mod_type, name, d);
}

/*
 * Iterate the AIE tile error report payload once: log every error and validate
 * each error column against the device geometry, then cache the last error into
 * aie->last_async_err (the field read under dev_lock by the GET_ARRAY query).
 * Returns true when the report is valid (at least one error and every column in
 * range). A column outside [0, metadata.cols) makes the whole report invalid so
 * the cache is not updated from unvalidated data. dev_lock is taken only around
 * the cache write; the iteration itself runs without the lock.
 */
static bool amdxdna_aie_backtrack_and_cache(struct aie_device *aie,
					    void *err_info, u32 num_err)
{
	struct amdxdna_async_error *rec = &aie->last_async_err;
	struct amdxdna_dev *xdna = aie->xdna;
	struct aie_error *errs = err_info;
	struct amdxdna_aie_err_decode d;
	struct aie_error *last_err;
	bool saw_valid_col = false;
	int i;

	for (i = 0; i < num_err; i++) {
		struct aie_error *err = &errs[i];

		amdxdna_aie_decode_one(aie, err->row, err->event_id, err->mod_type, &d);
		XDNA_ERR(xdna, "AIE error:");
		XDNA_ERR(xdna, "\tTile location (Row, Column): (%u, %u)", err->row, err->col);
		XDNA_ERR(xdna, "\tModule: %s", d.mod_str);
		XDNA_ERR(xdna, "\tCategory: %s", d.cat_str);
		XDNA_ERR(xdna, "\tEvent (ID): %s (%u)", d.event_str, err->event_id);

		if (err->col >= aie->metadata.cols) {
			XDNA_WARN(xdna, "Invalid column number %u", err->col);
			return false;
		}

		saw_valid_col = true;
	}

	if (!saw_valid_col)
		return false;

	/* Cache the last error for the GET_ARRAY query. */
	last_err = &errs[num_err - 1];
	amdxdna_aie_decode_one(aie, last_err->row, last_err->event_id, last_err->mod_type, &d);

	mutex_lock(&xdna->dev_lock);
	rec->err_code = AMDXDNA_ERROR_ENCODE(d.err_num, d.err_mod);
	rec->ts_us = ktime_to_us(ktime_get_real());
	rec->ex_err_code = AMDXDNA_EXTRA_ERR_ENCODE(last_err->row, last_err->col);
	mutex_unlock(&xdna->dev_lock);

	return true;
}

/*
 * Decode an AIE tile error report and cache the last error. A report that
 * cannot be parsed is logged and dropped; the caller has already re-armed the
 * slot. amdxdna_aie_backtrack_and_cache() takes dev_lock for the caching.
 */
static void amdxdna_aie_decode_tile_error(struct aie_device *aie,
					  void *vaddr, u32 buf_size)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct aie_err_info *info = vaddr;
	u32 max_err;

	/* The header read and max_err subtraction below need a full header. */
	if (unlikely(buf_size < sizeof(*info))) {
		XDNA_WARN(xdna, "Report buffer too small, %u bytes", buf_size);
		return;
	}

	XDNA_DBG(xdna, "Error count %d return code %d", info->err_cnt, info->ret_code);

	max_err = (buf_size - sizeof(*info)) / sizeof(struct aie_error);
	if (unlikely(info->err_cnt > max_err)) {
		/*
		 * err_cnt comes from the report firmware wrote, so this must
		 * not be a WARN: panic_on_warn would turn a malformed report
		 * into a panic.
		 */
		XDNA_WARN(xdna, "Error count too large %u", info->err_cnt);
		return;
	}

	if (!amdxdna_aie_backtrack_and_cache(aie, info->payload, info->err_cnt))
		XDNA_WARN(xdna, "No valid AIE error column found in report");
}

static int amdxdna_async_error_cb(void *handle, void __iomem *data, size_t size)
{
	struct amdxdna_async_event *e = handle;

	if (data) {
		e->resp.type = readl(data + offsetof(struct amdxdna_async_event_resp, type));
		wmb(); /* Update status in the end, so that no lock for here */
		e->resp.status = readl(data + offsetof(struct amdxdna_async_event_resp, status));
	}
	queue_work(e->events->wq, &e->work);
	return 0;
}

static int amdxdna_async_event_send(struct amdxdna_async_event *e)
{
	amdxdna_cache_flush(e->buf, e->size); /* device can access */
	return e->aie->xdna->dev_info->ops->register_async_event(e->aie, e->addr, e->size,
								 e, amdxdna_async_error_cb);
}

/*
 * Copy the report out of the slot buffer into the pool scratch buffer, so the
 * slot can be re-armed before the report is decoded. The whole buffer is
 * copied because the tile error decode takes its error limit from the length
 * it is given.
 *
 * No locking is needed: firmware does not write a slot while its worker runs,
 * and teardown drains the workqueue before freeing the scratch buffer or any
 * slot.
 *
 * Return: number of bytes copied.
 */
static u32 amdxdna_async_event_take_report(struct amdxdna_async_event *e)
{
	/* Never copy more than the scratch buffer holds. */
	u32 len = min_t(u32, e->size, ASYNC_BUF_SIZE);

	/* Invalidate stale cache lines before reading the device-written report. */
	amdxdna_cache_flush(e->buf, len);
	memcpy(e->events->scratch, e->buf, len);
	/*
	 * Clear the slot, so that a later report firmware writes only in part
	 * cannot carry bytes of this one. The dirty lines are written back by
	 * the flush in amdxdna_async_event_send() before firmware gets the
	 * buffer again.
	 */
	memset(e->buf, 0, len);

	return len;
}

static void amdxdna_async_event_rearm(struct amdxdna_async_event *e)
{
	struct amdxdna_dev *xdna = e->aie->xdna;

	mutex_lock(&xdna->dev_lock);
	/*
	 * Do not re-arm an unarmed pool. The unarm path clears armed under
	 * dev_lock before it drains this worker, so the worker never sends on a
	 * stopped channel. A timed-out management message destroys the channel
	 * under dev_lock while the pool stays armed, so check for that too.
	 */
	if (e->events->armed && e->aie->mgmt_chann && amdxdna_async_event_send(e))
		XDNA_WARN(xdna, "Unable to register async event");
	mutex_unlock(&xdna->dev_lock);
}

/*
 * Decode @report, the worker's copy of the slot buffer. @type is passed in
 * because the slot is already re-armed, so its resp.type may belong to a newer
 * event. @report is memory the device never sees, so it needs no cache
 * maintenance.
 */
static void amdxdna_async_event_decode(struct amdxdna_async_event *e, u32 type,
				       void *report, u32 size)
{
	const struct amdxdna_dev_info *info = e->aie->xdna->dev_info;
	struct aie_device *aie = e->aie;

	print_hex_dump_debug("AIE error: ", DUMP_PREFIX_OFFSET, 16, 4, report, 0x100, false);

	/* Call the device handler without dev_lock; it may take dev_lock itself. */
	if (info->ops->handle_dev_async_event &&
	    info->ops->handle_dev_async_event(aie, type, report))
		return;

	amdxdna_aie_decode_tile_error(aie, report, size);
}

static void amdxdna_async_error_worker(struct work_struct *err_work)
{
	struct amdxdna_async_event *e = container_of(err_work, struct amdxdna_async_event, work);
	const struct amdxdna_dev_info *info = e->aie->xdna->dev_info;
	struct amdxdna_dev *xdna = e->aie->xdna;
	u32 status = e->resp.status;
	u32 size;
	u32 type;

	/* The copy below dereferences the slot buffer. */
	if (drm_WARN_ON(&xdna->ddev, !e->hdl))
		return;

	/*
	 * On mailbox channel teardown the registered-event callback runs with
	 * data == NULL (see xdna_mailbox_stop_channel), which leaves resp.status
	 * at the sentinel. Skip decode and re-registration in that case so the
	 * dying channel is not touched. Stay silent, since this happens for
	 * every armed slot on every hw stop.
	 */
	if (status == info->async_error->max_status_code)
		return;

	e->resp.status = info->async_error->max_status_code;

	/* Once the slot is re-armed, firmware may overwrite resp.type. */
	type = e->resp.type;
	size = amdxdna_async_event_take_report(e);

	/*
	 * The slot buffer is cleared before every arm, so a completion that
	 * left it all zero carries no report, whatever its type: firmware
	 * refused the registration or could not write the report, and would
	 * fail the same buffer the same way again, so leave the slot unarmed.
	 * A nonzero status alone is not enough, because aie2 firmware completes
	 * a partial report with AIE_BACKTRACK_ERROR. The slot gets no
	 * completion until the next arm, so this warns at most once per slot
	 * per arm.
	 */
	if (status && !memchr_inv(e->events->scratch, 0, size)) {
		XDNA_WARN(xdna, "Async event completed with status 0x%x, slot idle", status);
		return;
	}

	/*
	 * Re-arm the slot before decoding: firmware holds only a few buffers,
	 * and decoding can be slow because it takes dev_lock and may reset a
	 * context. The slot is re-armed even if the report then fails to
	 * decode, so a bad report does not cost a slot for good.
	 */
	amdxdna_async_event_rearm(e);
	amdxdna_async_event_decode(e, type, e->events->scratch, size);
}

/**
 * amdxdna_async_events_alloc - allocate the async error report pool.
 * @aie: shared aie device the pool belongs to.
 * @num_events: number of report slots to allocate. Zero gives a pool that hands
 *	firmware no buffer and only carries the firmware notifications.
 *
 * Sends no firmware message, so it can run early in probe. A pool that gets
 * fewer buffers than requested, even none, is kept with a warning: a shorter
 * report queue is better than none, and a pool without buffers still carries
 * the firmware notifications. Caller must hold dev_lock.
 *
 * Return: 0 on success, -ENOMEM if the pool itself cannot be allocated.
 */
int amdxdna_async_events_alloc(struct aie_device *aie, u32 num_events)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_async_events *events;
	int i, ret = 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	events = kzalloc_flex(*events, event, num_events);
	if (!events)
		return -ENOMEM;

	/* Set for __counted_by before the loop; trimmed below if short. */
	events->slot_cnt = num_events;

	/* Named per device: the PF and each VF have a pool of their own. */
	events->wq = alloc_ordered_workqueue("amdxdna_async_err_%s", 0,
					     dev_name(xdna->ddev.dev));
	if (!events->wq) {
		ret = -ENOMEM;
		goto free_events;
	}

	/*
	 * The report worker decodes from this copy so that it can re-arm the
	 * slot first, so no slot is kept without it.
	 */
	if (num_events) {
		events->scratch = kvzalloc(ASYNC_BUF_SIZE, GFP_KERNEL);
		if (!events->scratch)
			ret = -ENOMEM;
	}

	for (i = 0; events->scratch && i < num_events; i++) {
		struct amdxdna_async_event *e = &events->event[i];
		struct amdxdna_msg_buf_hdl *hdl;

		hdl = amdxdna_alloc_msg_buff(xdna, ASYNC_BUF_SIZE);
		if (IS_ERR(hdl)) {
			ret = PTR_ERR(hdl);
			break;
		}

		/*
		 * A slot keeps this buffer from probe to remove: the worker
		 * copies reports out instead of replacing it.
		 */
		e->hdl = hdl;
		e->addr = to_dma_addr(hdl, 0);
		e->buf = to_cpu_addr(hdl, 0);
		e->size = ASYNC_BUF_SIZE;

		INIT_WORK(&e->work, amdxdna_async_error_worker);
		e->resp.status = xdna->dev_info->async_error->max_status_code;
		e->events = events;
		e->aie = aie;
	}

	if (i < num_events) {
		XDNA_WARN(xdna, "Async event pool got %d of %u buffers, ret %d",
			  i, num_events, ret);
		events->slot_cnt = i;
	}

	/* A pool without slots takes no report and needs no copy. */
	if (!events->slot_cnt) {
		kvfree(events->scratch);
		events->scratch = NULL;
	}

	/*
	 * Pairs with the acquire in amdxdna_async_events_queue_work(), which
	 * reads the pool without dev_lock: a reader that sees the pointer must
	 * also see the workqueue.
	 */
	smp_store_release(&aie->async_events, events);

	XDNA_DBG(xdna, "Async event count %u, per-event buf size 0x%x",
		 events->slot_cnt, ASYNC_BUF_SIZE);
	return 0;

free_events:
	kfree(events);
	return ret;
}

/**
 * amdxdna_async_events_init - register the pre-allocated slots with firmware.
 * @aie: shared aie device holding the pool.
 *
 * Called from hw start once the mailbox is up. Arms every slot; the slot count
 * sets how many reports firmware can queue, and each report covers the whole
 * array.
 *
 * On a partial failure the pool is left unarmed. The caller then tears down the
 * mailbox and drains the workers of the slots that were armed, with
 * amdxdna_async_events_fini() or, when probe fails,
 * amdxdna_async_events_free(). Caller must hold dev_lock.
 *
 * Return: 0 on success, negative error code on failure.
 */
int amdxdna_async_events_init(struct aie_device *aie)
{
	struct amdxdna_async_events *events = aie->async_events;
	struct amdxdna_dev *xdna = aie->xdna;
	int i, ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	/* A report arriving during the loop is re-armed once dev_lock drops. */
	events->armed = true;

	for (i = 0; i < events->slot_cnt; i++) {
		struct amdxdna_async_event *e = &events->event[i];

		e->resp.status = xdna->dev_info->async_error->max_status_code;

		/*
		 * Clear the buffer on every arm. A report left in it when the
		 * mailbox was torn down was never copied out, and a later,
		 * shorter firmware write would let its bytes reach the error
		 * userspace reads back. The send below flushes the buffer.
		 */
		memset(e->buf, 0, e->size);

		ret = amdxdna_async_event_send(e);
		if (ret) {
			XDNA_ERR(xdna, "Register async event %d failed, ret %d", i, ret);
			events->armed = false;
			return ret;
		}
	}

	XDNA_DBG(xdna, "Registered %u async events", events->slot_cnt);
	return 0;
}

/**
 * amdxdna_async_events_fini - unarm the slots and drain their workers.
 * @aie: shared aie device holding the pool.
 *
 * Called from hw stop and from the hw start error unwind, after the mailbox is
 * torn down. Keeps the buffers, so a later hw start only has to re-arm them.
 * On return no worker is running, so this is safe on a pool that was never
 * armed and safe to call twice.
 *
 * Caller must hold dev_lock, which is dropped while the workqueue drains. No
 * other path may arm the pool meanwhile; none does, because every arm and
 * unarm runs within a single hw start, hw stop, suspend, resume or reset.
 */
void amdxdna_async_events_fini(struct aie_device *aie)
{
	struct amdxdna_async_events *events = aie->async_events;
	struct amdxdna_dev *xdna = aie->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!events)
		return;

	events->armed = false;

	/* Drop dev_lock so in-flight workers can complete before returning. */
	mutex_unlock(&xdna->dev_lock);
	flush_workqueue(events->wq);
	mutex_lock(&xdna->dev_lock);
}

bool amdxdna_async_events_queue_work(struct aie_device *aie, struct work_struct *work)
{
	/* Pairs with the release in amdxdna_async_events_alloc(). */
	struct amdxdna_async_events *events = smp_load_acquire(&aie->async_events);

	if (!events || !events->wq)
		return false;

	queue_work(events->wq, work);
	return true;
}

/**
 * amdxdna_async_events_free - release the async error report pool.
 * @aie: shared aie device holding the pool.
 *
 * Called from remove and from the probe unwinds, after the mailbox is torn down
 * and the firmware is stopped or suspended, the same rule the aie4 work buffer
 * follows. Caller must hold dev_lock, which is dropped while the workqueue is
 * destroyed.
 */
void amdxdna_async_events_free(struct aie_device *aie)
{
	struct amdxdna_async_events *events = aie->async_events;
	struct amdxdna_dev *xdna = aie->xdna;
	u32 i;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!events)
		return;

	events->armed = false;
	/*
	 * Retire the pool with a single store the lockless reader in
	 * amdxdna_async_events_queue_work() cannot tear. Callers stop the
	 * mailbox before getting here, so no async callback can race the
	 * destroy_workqueue() below; the release only keeps the pointer
	 * accesses symmetric with the publish in amdxdna_async_events_alloc().
	 */
	smp_store_release(&aie->async_events, NULL);

	/* Drop dev_lock so in-flight workers can complete before teardown. */
	mutex_unlock(&xdna->dev_lock);
	destroy_workqueue(events->wq);
	mutex_lock(&xdna->dev_lock);

	for (i = 0; i < events->slot_cnt; i++)
		amdxdna_free_msg_buff(events->event[i].hdl);
	kvfree(events->scratch);
	kfree(events);
}

/**
 * amdxdna_get_array_last_async_error - return the last asynchronous error.
 * @aie: shared aie device holding the cached error.
 * @args: GET_ARRAY ioctl arguments.
 *
 * Today only the single most recent async error is cached. Caller must hold
 * dev_lock.
 *
 * Return: 0 on success, negative error code on failure.
 */
int amdxdna_get_array_last_async_error(struct aie_device *aie,
				       struct amdxdna_drm_get_array *args)
{
	struct amdxdna_async_error *last = &aie->last_async_err;

	if (!args->num_element)
		return -EINVAL;

	args->num_element = 1;
	args->element_size = min(args->element_size, sizeof(*last));
	if (copy_to_user(u64_to_user_ptr(args->buffer), last, args->element_size))
		return -EFAULT;

	return 0;
}
