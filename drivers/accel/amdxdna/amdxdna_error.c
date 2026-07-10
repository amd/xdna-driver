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
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include "aie.h"
#include "amdxdna_error.h"
#include "amdxdna_pci_drv.h"

/* Private workqueue name (also the worker/rescuer thread name). */
#define AMDXDNA_ASYNC_ERR_WQ_NAME	"amdxdna_async_err"

/*
 * The AIE tile error report payload layout below is defined by the AIE device
 * and is common to the aie2 and aie4 firmware. The categorization of an
 * event_id (which category / driver error number it maps to) is specific to the
 * AIE generation, so it is NOT here: each back end supplies its own tables via
 * struct amdxdna_dev_info.luts.
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
 * @wq: ordered workqueue draining the report workers.
 * @event_cnt: number of slots (one per column).
 * @event: per column event slots, each with its own message buffer.
 */
struct amdxdna_async_events {
	struct workqueue_struct		*wq;
	u32				event_cnt;
	struct amdxdna_async_event	event[] __counted_by(event_cnt);
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
	const struct aie_error_lut_set *set = aie->xdna->dev_info->luts;
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
 * Decode one AIE tile error into @d using the arch's category tables (ops->luts)
 * for the category and event name, then the shared num/module/string mapping.
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
 * Decode an AIE tile error report and cache the last error. Returns true when
 * the report was valid and the slot should be re-registered, false otherwise.
 * The last-error caching (and its dev_lock) is handled inside
 * amdxdna_aie_backtrack_and_cache().
 */
static bool amdxdna_aie_decode_tile_error(struct aie_device *aie,
					  void *vaddr, u32 buf_size)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct aie_err_info *info = vaddr;
	u32 max_err;

	XDNA_DBG(xdna, "Error count %d return code %d", info->err_cnt, info->ret_code);

	max_err = (buf_size - sizeof(*info)) / sizeof(struct aie_error);
	if (unlikely(info->err_cnt > max_err)) {
		WARN_ONCE(1, "Error count too large %d\n", info->err_cnt);
		return false;
	}

	if (!amdxdna_aie_backtrack_and_cache(aie, info->payload, info->err_cnt)) {
		XDNA_WARN(xdna, "No valid AIE error column found in report");
		return false;
	}

	return true;
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
	drm_clflush_virt_range(e->buf, e->size); /* device can access */
	return e->aie->xdna->dev_info->ops->register_async_event(e->aie, e->addr, e->size,
								 e, amdxdna_async_error_cb);
}

static void amdxdna_async_error_worker(struct work_struct *err_work)
{
	struct amdxdna_async_event *e = container_of(err_work, struct amdxdna_async_event, work);
	const struct amdxdna_dev_info *info = e->aie->xdna->dev_info;
	struct amdxdna_dev *xdna = e->aie->xdna;
	struct aie_device *aie = e->aie;

	/*
	 * On mailbox channel teardown the registered-event callback runs with
	 * data == NULL (see xdna_mailbox_stop_channel), which leaves resp.status
	 * at the sentinel. Skip decode and re-registration in that case so the
	 * dying channel is not touched.
	 */
	if (e->resp.status == info->async_max_status_code)
		return;

	e->resp.status = info->async_max_status_code;

	/* Invalidate stale cache lines before reading the device-written report. */
	drm_clflush_virt_range(e->buf, e->size);

	print_hex_dump_debug("AIE error: ", DUMP_PREFIX_OFFSET, 16, 4, e->buf, 0x100, false);

	/* Call the device handler without dev_lock; it may take dev_lock itself. */
	if (info->ops->handle_dev_async_event &&
	    info->ops->handle_dev_async_event(aie, e->resp.type, e->buf))
		goto reregister;

	if (!amdxdna_aie_decode_tile_error(aie, e->buf, e->size))
		return; /* invalid report: do not re-register */

reregister:
	mutex_lock(&xdna->dev_lock);
	/*
	 * Skip re-registration if the event pool is being torn down. The free
	 * path clears async_events under dev_lock before draining this worker,
	 * so a drained worker cannot re-arm firmware on an already-stopped
	 * mailbox channel.
	 */
	if (aie->async_events && amdxdna_async_event_send(e))
		XDNA_WARN(xdna, "Unable to register async event");
	mutex_unlock(&xdna->dev_lock);
}

int amdxdna_async_events_alloc(struct aie_device *aie,
			       u32 total_col)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_async_events *events;
	int i, ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	events = kzalloc_flex(*events, event, total_col);
	if (!events)
		return -ENOMEM;

	events->event_cnt = total_col;

	events->wq = alloc_ordered_workqueue(AMDXDNA_ASYNC_ERR_WQ_NAME, 0);
	if (!events->wq) {
		kfree(events);
		return -ENOMEM;
	}

	/*
	 * Publish the pool before arming firmware. amdxdna_async_event_send()
	 * leaves a mailbox message holding &event[i] as its handle, so on a
	 * partial-registration failure the pool must outlive the mailbox
	 * channel. The caller's hw_start() error unwind stops the mailbox and
	 * then calls amdxdna_async_events_free(), which drains the workqueue and
	 * frees the (NULL-safe) slots once firmware can no longer DMA into or
	 * fire the callback on them.
	 */
	aie->async_events = events;

	for (i = 0; i < events->event_cnt; i++) {
		struct amdxdna_async_event *e = &events->event[i];

		e->hdl = amdxdna_alloc_msg_buff(xdna, ASYNC_BUF_SIZE);
		if (IS_ERR(e->hdl)) {
			ret = PTR_ERR(e->hdl);
			e->hdl = NULL;
			return ret;
		}

		INIT_WORK(&e->work, amdxdna_async_error_worker);

		e->resp.status = xdna->dev_info->async_max_status_code;
		e->addr = to_dma_addr(e->hdl, 0);
		e->buf = to_cpu_addr(e->hdl, 0);
		e->size = ASYNC_BUF_SIZE;
		e->events = events;
		e->aie = aie;

		ret = amdxdna_async_event_send(e);
		if (ret) {
			amdxdna_free_msg_buff(e->hdl);
			e->hdl = NULL;
			return ret;
		}
	}

	XDNA_DBG(xdna, "Async event count %d, per-event buf size 0x%x",
		 events->event_cnt, ASYNC_BUF_SIZE);
	return 0;
}

void amdxdna_async_events_free(struct aie_device *aie)
{
	struct amdxdna_dev *xdna = aie->xdna;
	struct amdxdna_async_events *events = aie->async_events;
	int i;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!events)
		return;

	aie->async_events = NULL;

	/* Drop dev_lock so in-flight workers can complete before teardown. */
	mutex_unlock(&xdna->dev_lock);
	destroy_workqueue(events->wq);
	mutex_lock(&xdna->dev_lock);

	for (i = 0; i < events->event_cnt; i++)
		amdxdna_free_msg_buff(events->event[i].hdl);
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
