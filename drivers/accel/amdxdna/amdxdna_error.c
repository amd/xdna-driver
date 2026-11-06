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
 * @refusal_logged: set once this slot has reported a refusal, cleared when the
 * slot is armed.
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
	bool				refusal_logged;
	struct amdxdna_async_event_resp	resp;
};

/**
 * struct amdxdna_async_events - pool of async error report buffer slots
 * @wq: ordered workqueue draining the report workers.
 * @scratch: ASYNC_BUF_SIZE staging buffer the report worker decodes from.
 * @armed_cnt: gate for the re-arm path: zero while the pool is unarmed,
 *             otherwise the slot count the arming loop registered. Not a
 *             running total of live registrations: init() zeroes it if any
 *             slot fails to register, a re-arm that fails only warns, and a
 *             management timeout leaves it counting slots whose channel is
 *             gone. Written and read under dev_lock.
 * @held_cnt: number of slots whose buffer address firmware has been handed.
 *            Only the probe unwind paths consult it, and only there is it
 *            maintained precisely; elsewhere it may over-count, because
 *            amdxdna_async_events_released() is the sole thing that clears it
 *            and the teardown path lets firmware release the registrations
 *            without reporting that back. Over-counting is the safe
 *            direction: it can only widen what a failed probe leaks, never
 *            free a buffer firmware still holds. Unlike @armed_cnt the count
 *            survives an unarm, because unarming is local to the driver and
 *            tells firmware nothing. Written and read under dev_lock.
 * @slot_cnt: number of slots that hold a report buffer, which may be fewer than
 *            the caller asked for.
 * @event: event slots, each with its own message buffer.
 *
 * The pool is allocated once at probe and released at device teardown, while
 * the slots are only registered with firmware between hw start and hw stop.
 * The buffers therefore outlive the mailbox channel, so a resume never has to
 * allocate and a mailbox message that still holds a slot as its callback handle
 * can never point at freed memory.
 *
 * One scratch buffer serves the whole pool rather than one per slot, because
 * @wq is ordered: it runs at most one work item at a time, so two report
 * workers can never be decoding at once.
 */
struct amdxdna_async_events {
	struct workqueue_struct		*wq;
	void				*scratch;
	u32				armed_cnt;
	u32				held_cnt;
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
 * Decode an AIE tile error report and cache the last error. A report the driver
 * cannot parse is logged and dropped; it does not affect the slot, which the
 * caller re-arms either way. The last-error caching (and its dev_lock) is
 * handled inside amdxdna_aie_backtrack_and_cache().
 */
static void amdxdna_aie_decode_tile_error(struct aie_device *aie,
					  void *vaddr, u32 buf_size)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct aie_err_info *info = vaddr;
	u32 max_err;

	/* Both the header read below and the max_err subtraction need this. */
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
	e->refusal_logged = false;
	amdxdna_cache_flush(e->buf, e->size); /* device can access */
	return e->aie->xdna->dev_info->ops->register_async_event(e->aie, e->addr, e->size,
								 e, amdxdna_async_error_cb);
}

/*
 * Take the report firmware has just written out of the slot buffer and into the
 * pool scratch buffer, so that the slot can be armed again with the buffer it
 * already owns before the report is decoded.
 *
 * The whole buffer is copied. A tile error report is variable length and
 * amdxdna_aie_decode_tile_error() derives how many errors it will accept from
 * the size it is handed, so a report that legitimately filled the buffer would
 * be dropped if less were taken.
 *
 * No locking is needed: the slot is unarmed while its worker runs, so firmware
 * cannot be writing the buffer, and the pool teardown path drains this
 * workqueue before it releases the scratch buffer or any slot.
 *
 * Return: number of bytes copied, which bounds the decode.
 */
static u32 amdxdna_async_event_take_report(struct amdxdna_async_event *e)
{
	/* The scratch buffer is ASYNC_BUF_SIZE; do not outrun it. */
	u32 len = min_t(u32, e->size, ASYNC_BUF_SIZE);

	/* Invalidate stale cache lines before reading the device-written report. */
	amdxdna_cache_flush(e->buf, len);
	memcpy(e->events->scratch, e->buf, len);
	/*
	 * Clear the slot behind the copy, so a report firmware fills only in
	 * part cannot carry bytes of the report before it. That leaves the
	 * lines dirty, which is safe because every path that hands the buffer
	 * back to firmware flushes it first in amdxdna_async_event_send(), and
	 * amdxdna_cache_flush() writes back before it invalidates.
	 */
	memset(e->buf, 0, len);

	return len;
}

static void amdxdna_async_event_rearm(struct amdxdna_async_event *e)
{
	struct amdxdna_dev *xdna = e->aie->xdna;

	mutex_lock(&xdna->dev_lock);
	/*
	 * Skip re-registration once the slots have been unarmed. The unarm path
	 * zeroes armed_cnt under dev_lock before draining this worker, so a
	 * drained worker cannot re-arm firmware on an already-stopped mailbox
	 * channel.
	 */
	if (e->events->armed_cnt && amdxdna_async_event_send(e))
		XDNA_WARN(xdna, "Unable to register async event");
	mutex_unlock(&xdna->dev_lock);
}

/*
 * Decode one consumed report out of @report, the copy the worker took. @type is
 * passed in rather than read from the slot because the slot is already re-armed
 * by this point, so its resp.type may describe a newer event. @report needs no
 * cache maintenance: it is ordinary kernel memory the device never sees.
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
	 * dying channel is not touched. This one stays silent: teardown fires
	 * the callback on every armed slot, on every hw stop.
	 */
	if (status == info->async_error->max_status_code)
		return;

	e->resp.status = info->async_error->max_status_code;

	/*
	 * Firmware refuses a registration once its async buffer stack is full,
	 * and answers on the slot itself rather than to the send that was
	 * refused, which returns before firmware has looked at it. There is no
	 * report behind such a completion, and re-arming the slot only earns
	 * another refusal, so retire the slot and say so once. Refusals come in
	 * batches, one per surplus slot, and unbounded logging here is what made
	 * this expensive rather than merely wrong.
	 */
	if (status == info->async_error->full_status_code) {
		if (!e->refusal_logged) {
			e->refusal_logged = true;
			XDNA_WARN(xdna, "Firmware refused the async event registration, slot idle");
		}
		return;
	}

	/*
	 * Snapshot the event type before re-arming: once the slot is armed again
	 * firmware may report a new event and overwrite resp.type while the
	 * report below is still being decoded.
	 */
	type = e->resp.type;

	/*
	 * Re-arm the slot ahead of decoding it. Firmware only holds a small
	 * number of async report buffers, and decoding can be slow (it takes
	 * dev_lock and may reset a context), so copy the report out and register
	 * the slot again first, then decode the copy at leisure. This keeps the
	 * window in which firmware is one buffer short as short as possible.
	 *
	 * The slot is re-armed whether or not the report decodes cleanly: a
	 * report the driver cannot parse is no reason to retire the slot and
	 * leave firmware one report of queue depth short for good.
	 */
	size = amdxdna_async_event_take_report(e);
	amdxdna_async_event_rearm(e);
	amdxdna_async_event_decode(e, type, e->events->scratch, size);
}

/**
 * amdxdna_async_events_alloc - allocate the async error report pool.
 * @aie: shared aie device the pool belongs to.
 * @num_events: number of report slots to allocate.
 *
 * Only allocates memory and sends no firmware message, so this is safe to fail
 * early in probe. A pool that gets fewer buffers than the caller asked for is
 * kept and reported, since a shorter report queue beats no reporting at all.
 * Caller must hold dev_lock.
 *
 * Return: 0 on success, negative error code on failure.
 */
int amdxdna_async_events_alloc(struct aie_device *aie, u32 num_events)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_async_events *events;
	int i, ret = 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!num_events)
		return -EINVAL;

	events = kzalloc_flex(*events, event, num_events);
	if (!events)
		return -ENOMEM;

	/* Bounds the __counted_by accesses below; trimmed to what was allocated. */
	events->slot_cnt = num_events;

	/* Named per device: the PF and every VF have a pool of their own. */
	events->wq = alloc_ordered_workqueue("amdxdna_async_err_%s", 0,
					     dev_name(xdna->ddev.dev));
	if (!events->wq) {
		ret = -ENOMEM;
		goto free_events;
	}

	/*
	 * The report worker decodes out of here instead of out of the slot
	 * buffer, which is what lets it re-arm a slot without allocating a
	 * replacement for it. A pool without one could take no report at all,
	 * so treat this like the zero-buffer case below and fail.
	 */
	events->scratch = kvzalloc(ASYNC_BUF_SIZE, GFP_KERNEL);
	if (!events->scratch) {
		ret = -ENOMEM;
		goto destroy_wq;
	}

	for (i = 0; i < num_events; i++) {
		struct amdxdna_async_event *e = &events->event[i];
		struct amdxdna_msg_buf_hdl *hdl;

		hdl = amdxdna_alloc_msg_buff(xdna, ASYNC_BUF_SIZE);
		if (IS_ERR(hdl)) {
			ret = PTR_ERR(hdl);
			break;
		}

		/*
		 * The only place a slot is bound to a buffer: the worker copies
		 * reports out rather than replacing this, so the binding holds
		 * from probe to remove.
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

	/* Nothing to arm, so firmware would have nowhere to report at all. */
	if (!i)
		goto free_scratch;

	if (i < num_events) {
		XDNA_WARN(xdna, "Async event pool got %d of %u buffers, ret %d",
			  i, num_events, ret);
		events->slot_cnt = i;
	}

	/*
	 * Publish the finished pool with a release store, pairing with the
	 * acquire in amdxdna_async_events_queue_work(): the mailbox async
	 * callback reads the pool without dev_lock to reach its workqueue, so a
	 * reader that sees the pointer has to see the workqueue and the trimmed
	 * slot count too. Nothing is armed yet, and this runs before the mailbox
	 * exists, so no reader can be running here today.
	 */
	smp_store_release(&aie->async_events, events);

	XDNA_DBG(xdna, "Async event count %d, per-event buf size 0x%x",
		 events->slot_cnt, ASYNC_BUF_SIZE);
	return 0;

free_scratch:
	kvfree(events->scratch);
destroy_wq:
	destroy_workqueue(events->wq);
free_events:
	kfree(events);
	return ret;
}

/**
 * amdxdna_async_events_init - register the pre-allocated slots with firmware.
 * @aie: shared aie device holding the pool.
 *
 * Called from hw start, once the mailbox is up. Arms every slot the pool holds,
 * which sets how many reports firmware can queue rather than which columns are
 * covered: firmware backtracks every column of an event into the single buffer
 * it takes for that event, so one armed slot already covers the whole array.
 * Callers size the pool by AMDXDNA_MAX_ASYNC_EVENT_BUFS, which the management
 * mailbox channel is sized against.
 *
 * A partial failure unarms the pool before returning, so the already-armed
 * slots are not re-armed by their workers; the caller still unwinds by tearing
 * down the mailbox and calling amdxdna_async_events_fini() to drain those
 * workers. Caller must hold dev_lock.
 *
 * Return: 0 on success, negative error code on failure.
 */
int amdxdna_async_events_init(struct aie_device *aie)
{
	struct amdxdna_async_events *events = aie->async_events;
	struct amdxdna_dev *xdna = aie->xdna;
	u32 arm_cnt;
	int i, ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!events) {
		XDNA_ERR(xdna, "Async event pool was not allocated");
		return -ENODEV;
	}

	/* Never zero: alloc() fails a pool that got no buffer at all. */
	arm_cnt = events->slot_cnt;

	/*
	 * Publish the count before arming firmware so that a report arriving
	 * while this loop is still running is re-armed by its worker rather than
	 * silently left unarmed.
	 */
	events->armed_cnt = arm_cnt;

	for (i = 0; i < arm_cnt; i++) {
		struct amdxdna_async_event *e = &events->event[i];

		e->resp.status = xdna->dev_info->async_error->max_status_code;

		/*
		 * Hand firmware a cleared buffer on every arm, not just on the
		 * first. A slot keeps its buffer across a hw stop, and the report
		 * worker returns without clearing it when the mailbox was torn
		 * down under it, so residue from a report that was never taken
		 * can still be here. The decode path trusts err_cnt and the
		 * payload it bounds, so a firmware write shorter than the report
		 * would otherwise leave that residue to be decoded into the
		 * cached error userspace reads back. The send below flushes this
		 * range before firmware is told about it.
		 */
		memset(e->buf, 0, e->size);

		/*
		 * Count the slot as handed over before the send rather than
		 * after: a send that reports a timeout may still have reached
		 * firmware, and -ETIME says nothing about what firmware took.
		 * The count only grows, because re-arming a slot hands over the
		 * address it already had and so cannot take one back.
		 */
		events->held_cnt = max_t(u32, events->held_cnt, i + 1);

		ret = amdxdna_async_event_send(e);
		if (ret) {
			XDNA_ERR(xdna, "Register async event %d failed, ret %d", i, ret);
			events->armed_cnt = 0;
			return ret;
		}
	}

	XDNA_DBG(xdna, "Registered %u async events", arm_cnt);
	return 0;
}

/**
 * amdxdna_async_events_fini - unarm the slots and drain their workers.
 * @aie: shared aie device holding the pool.
 *
 * Called from hw stop (and from the hw start error unwind) after the mailbox has
 * been torn down. Keeps the pool and its buffers allocated so that a later
 * resume only has to re-arm them. Caller must hold dev_lock; the lock is
 * dropped while the workqueue is drained.
 *
 * The drain runs whenever the pool exists rather than only when it is still
 * armed, so that returning from here means no report worker is in flight,
 * however the pool came to be unarmed. It is therefore safe to call on a pool
 * that was never armed and safe to call twice.
 *
 * That holds only because no caller arms the pool while another is draining
 * it. dev_lock is dropped around flush_workqueue(), so a concurrent
 * amdxdna_async_events_init() would re-arm slots behind the drain and let a
 * worker start after it returns. Every arm and unarm runs under a single
 * dev_lock hold on one hw start, hw stop, suspend, resume or reset path, so
 * the two cannot overlap.
 */
void amdxdna_async_events_fini(struct aie_device *aie)
{
	struct amdxdna_async_events *events = aie->async_events;
	struct amdxdna_dev *xdna = aie->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!events)
		return;

	events->armed_cnt = 0;

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
 * amdxdna_async_events_released - record that firmware gave the buffers back.
 * @aie: shared aie device holding the pool.
 *
 * Called by the back end once a release has actually been delivered to and
 * acknowledged by firmware. Until then the pool has to assume firmware still
 * has every address it was handed. Caller must hold dev_lock.
 *
 * The pool must already be unarmed. Clearing the count on an armed pool would
 * let a report worker re-arm a slot afterwards through
 * amdxdna_async_event_rearm(), which gates on @armed_cnt alone, and a later
 * amdxdna_async_events_abandon() would then free a buffer firmware holds.
 */
void amdxdna_async_events_released(struct aie_device *aie)
{
	struct amdxdna_async_events *events = aie->async_events;
	struct amdxdna_dev *xdna = aie->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!events)
		return;

	drm_WARN_ON(&xdna->ddev, events->armed_cnt);

	events->held_cnt = 0;
}

/*
 * Tear the pool down, freeing every slot buffer from @leak_cnt upwards and
 * leaving the ones below it allocated for good. Caller must hold dev_lock; the
 * lock is dropped while the workqueue is destroyed.
 */
static void amdxdna_async_events_destroy(struct aie_device *aie, u32 leak_cnt)
{
	struct amdxdna_async_events *events = aie->async_events;
	struct amdxdna_dev *xdna = aie->xdna;
	u32 i;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!events)
		return;

	events->armed_cnt = 0;
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

	for (i = leak_cnt; i < events->slot_cnt; i++)
		amdxdna_free_msg_buff(events->event[i].hdl);
	kvfree(events->scratch);
	kfree(events);
}

/**
 * amdxdna_async_events_free - release the async error report pool.
 * @aie: shared aie device holding the pool.
 *
 * Called once from the device fini (remove) path, after hw stop has unarmed the
 * slots. Caller must hold dev_lock; the lock is dropped while the workqueue is
 * destroyed.
 */
void amdxdna_async_events_free(struct aie_device *aie)
{
	amdxdna_async_events_destroy(aie, 0);
}

/**
 * amdxdna_async_events_abandon - release the pool from a failed probe.
 * @aie: shared aie device holding the pool.
 *
 * Frees the workqueue, the scratch buffer, the pool itself and every slot
 * buffer firmware was never handed, and deliberately never frees the rest.
 *
 * Firmware keeps the address of every slot the arming loop reached and writes a
 * report into it before it touches the mailbox, so the host cannot refuse the
 * write. It gives those addresses up only on a release it acknowledged, and a
 * VF can never obtain one: there is no unregister opcode, and firmware routes a
 * VF suspend past the code that clears the registry. Freeing such a buffer
 * would leave firmware writing into a reclaimed page, so the buffers below
 * @held_cnt stay allocated permanently. Nothing else does, so a failed probe
 * leaks at most the pool's worth of report buffers and no worker thread.
 *
 * Caller must hold dev_lock; the lock is dropped while the workqueue is
 * destroyed.
 */
void amdxdna_async_events_abandon(struct aie_device *aie)
{
	struct amdxdna_async_events *events = aie->async_events;
	struct amdxdna_dev *xdna = aie->xdna;
	u32 bytes = 0;
	u32 i;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!events)
		return;

	for (i = 0; i < events->held_cnt; i++)
		bytes += to_buf_size(events->event[i].hdl);

	if (events->held_cnt)
		XDNA_ERR(xdna, "Leaking %u async error buffers (%u bytes) firmware still holds",
			 events->held_cnt, bytes);

	amdxdna_async_events_destroy(aie, events->held_cnt);
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
