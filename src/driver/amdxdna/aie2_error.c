// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025, Advanced Micro Devices, Inc.
 */

#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/dma-mapping.h>
#include <drm/drm_cache.h>
#include "aie2_msg_priv.h"
#include "aie2_pci.h"

struct async_event {
	struct amdxdna_dev_hdl		*ndev;
	struct async_event_msg_resp	resp;
	struct workqueue_struct		*wq;
	struct work_struct		work;
	struct aie2_mgmt_dma_hdl	mgmt_hdl;
};

struct async_events {
	struct workqueue_struct		*wq;
	u32				event_cnt;
	struct async_event		event[] __counted_by(event_cnt);
};

/*
 * Below enum, struct and lookup tables are porting from XAIE util header file.
 *
 * Below data is defined by AIE device and it is used for decode error message
 * from the device.
 */

enum aie_module_type {
	AIE_MEM_MOD = 0,
	AIE_CORE_MOD,
	AIE_PL_MOD,
};

enum aie_error_category {
	AIE_ERROR_SATURATION = 0,
	AIE_ERROR_FP,
	AIE_ERROR_STREAM,
	AIE_ERROR_ACCESS,
	AIE_ERROR_BUS,
	AIE_ERROR_INSTRUCTION,
	AIE_ERROR_ECC,
	AIE_ERROR_LOCK,
	AIE_ERROR_DMA,
	AIE_ERROR_MEM_PARITY,
	/* Unknown is not from XAIE, added for better category */
	AIE_ERROR_UNKNOWN,
};

/* Don't pack, unless XAIE side changed */
struct aie_error {
	u8			row;
	u8			col;
	u16			reserved_0;
	u32			mod_type;
	u8			event_id;
	u8			reserved_1;
	u16			reserved_2;
};

struct aie_err_info {
	u32			err_cnt;
	u32			ret_code;
	u32			rsvd;
	struct aie_error	payload[] __counted_by(err_cnt);
};

struct aie_event_category {
	u8			event_id;
	enum aie_error_category category;
};

struct aie_cat_xrt_err_num {
	enum aie_error_category category;
	enum xrt_error_num xrt_num;
};

struct aie_mod_xrt_err_mod {
	enum aie_module_type mod_type;
	enum xrt_error_module xrt_mod;
};

#define EVENT_CATEGORY(id, cat) { id, cat }
static const struct aie_event_category aie_ml_mem_event_cat[] = {
	EVENT_CATEGORY(88U,  AIE_ERROR_ECC),
	EVENT_CATEGORY(90U,  AIE_ERROR_ECC),
	EVENT_CATEGORY(91U,  AIE_ERROR_MEM_PARITY),
	EVENT_CATEGORY(92U,  AIE_ERROR_MEM_PARITY),
	EVENT_CATEGORY(93U,  AIE_ERROR_MEM_PARITY),
	EVENT_CATEGORY(94U,  AIE_ERROR_MEM_PARITY),
	EVENT_CATEGORY(95U,  AIE_ERROR_MEM_PARITY),
	EVENT_CATEGORY(96U,  AIE_ERROR_MEM_PARITY),
	EVENT_CATEGORY(97U,  AIE_ERROR_DMA),
	EVENT_CATEGORY(98U,  AIE_ERROR_DMA),
	EVENT_CATEGORY(99U,  AIE_ERROR_DMA),
	EVENT_CATEGORY(100U, AIE_ERROR_DMA),
	EVENT_CATEGORY(101U, AIE_ERROR_LOCK),
};

static const struct aie_event_category aie_ml_core_event_cat[] = {
	EVENT_CATEGORY(55U, AIE_ERROR_ACCESS),
	EVENT_CATEGORY(56U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(57U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(58U, AIE_ERROR_BUS),
	EVENT_CATEGORY(59U, AIE_ERROR_INSTRUCTION),
	EVENT_CATEGORY(60U, AIE_ERROR_ACCESS),
	EVENT_CATEGORY(62U, AIE_ERROR_ECC),
	EVENT_CATEGORY(64U, AIE_ERROR_ECC),
	EVENT_CATEGORY(65U, AIE_ERROR_ACCESS),
	EVENT_CATEGORY(66U, AIE_ERROR_ACCESS),
	EVENT_CATEGORY(67U, AIE_ERROR_LOCK),
	EVENT_CATEGORY(70U, AIE_ERROR_INSTRUCTION),
	EVENT_CATEGORY(71U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(72U, AIE_ERROR_BUS),
};

static const struct aie_event_category aie_ml_mem_tile_event_cat[] = {
	EVENT_CATEGORY(130U, AIE_ERROR_ECC),
	EVENT_CATEGORY(132U, AIE_ERROR_ECC),
	EVENT_CATEGORY(133U, AIE_ERROR_DMA),
	EVENT_CATEGORY(134U, AIE_ERROR_DMA),
	EVENT_CATEGORY(135U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(136U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(137U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(138U, AIE_ERROR_BUS),
	EVENT_CATEGORY(139U, AIE_ERROR_LOCK),
};

static const struct aie_event_category aie_ml_shim_tile_event_cat[] = {
	EVENT_CATEGORY(64U, AIE_ERROR_BUS),
	EVENT_CATEGORY(65U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(66U, AIE_ERROR_STREAM),
	EVENT_CATEGORY(67U, AIE_ERROR_BUS),
	EVENT_CATEGORY(68U, AIE_ERROR_BUS),
	EVENT_CATEGORY(69U, AIE_ERROR_BUS),
	EVENT_CATEGORY(70U, AIE_ERROR_BUS),
	EVENT_CATEGORY(71U, AIE_ERROR_BUS),
	EVENT_CATEGORY(72U, AIE_ERROR_DMA),
	EVENT_CATEGORY(73U, AIE_ERROR_DMA),
	EVENT_CATEGORY(74U, AIE_ERROR_LOCK),
};

static const struct aie_cat_xrt_err_num aie_cat_err_num_map[] = {
	{ AIE_ERROR_SATURATION, XRT_ERROR_NUM_AIE_SATURATION },
	{ AIE_ERROR_FP, XRT_ERROR_NUM_AIE_FP },
	{ AIE_ERROR_STREAM, XRT_ERROR_NUM_AIE_STREAM },
	{ AIE_ERROR_ACCESS, XRT_ERROR_NUM_AIE_ACCESS },
	{ AIE_ERROR_BUS, XRT_ERROR_NUM_AIE_BUS },
	{ AIE_ERROR_INSTRUCTION, XRT_ERROR_NUM_AIE_INSTRUCTION },
	{ AIE_ERROR_ECC, XRT_ERROR_NUM_AIE_ECC },
	{ AIE_ERROR_LOCK, XRT_ERROR_NUM_AIE_LOCK },
	{ AIE_ERROR_DMA, XRT_ERROR_NUM_AIE_DMA },
	{ AIE_ERROR_MEM_PARITY, XRT_ERROR_NUM_AIE_MEM_PARITY },
};

static const struct aie_mod_xrt_err_mod aie_mod_xrt_err_mod_map[] = {
	{ AIE_MEM_MOD, XRT_ERROR_MODULE_AIE_MEMORY },
	{ AIE_CORE_MOD, XRT_ERROR_MODULE_AIE_CORE },
	{ AIE_PL_MOD, XRT_ERROR_MODULE_AIE_PL },
};

static enum xrt_error_module aie_get_xrt_error_mod(enum aie_module_type mod_type)
{
	for (int i = 0; i < ARRAY_SIZE(aie_mod_xrt_err_mod_map); i++) {
		if (aie_mod_xrt_err_mod_map[i].mod_type == mod_type)
			return aie_mod_xrt_err_mod_map[i].xrt_mod;
	}
	return XRT_ERROR_MODULE_UNKNOWN;
}

static enum xrt_error_num aie_err_cat_get_xrt_err_num(enum aie_error_category cat)
{
	for (int i = 0; i < ARRAY_SIZE(aie_cat_err_num_map); i++) {
		if (aie_cat_err_num_map[i].category == cat)
			return aie_cat_err_num_map[i].xrt_num;
	}
	return XRT_ERROR_NUM_UNKNOWN;
}

static enum aie_error_category
aie_get_error_category(u8 row, u8 event_id, enum aie_module_type mod_type)
{
	const struct aie_event_category *lut;
	int num_entry;
	int i;

	switch (mod_type) {
	case AIE_PL_MOD:
		lut = aie_ml_shim_tile_event_cat;
		num_entry = ARRAY_SIZE(aie_ml_shim_tile_event_cat);
		break;
	case AIE_CORE_MOD:
		lut = aie_ml_core_event_cat;
		num_entry = ARRAY_SIZE(aie_ml_core_event_cat);
		break;
	case AIE_MEM_MOD:
		if (row == 1) {
			lut = aie_ml_mem_tile_event_cat;
			num_entry = ARRAY_SIZE(aie_ml_mem_tile_event_cat);
		} else {
			lut = aie_ml_mem_event_cat;
			num_entry = ARRAY_SIZE(aie_ml_mem_event_cat);
		}
		break;
	default:
		return AIE_ERROR_UNKNOWN;
	}

	for (i = 0; i < num_entry; i++) {
		if (event_id != lut[i].event_id)
			continue;

		return lut[i].category;
	}

	return AIE_ERROR_UNKNOWN;
}

static void aie2_async_errors_cache(struct amdxdna_dev_hdl *ndev, void *err_info, u32 num_err)
{
	struct amdxdna_async_error *record = &ndev->async_errs_cache.err;
	u64 current_time_us = ktime_to_us(ktime_get_real());
	struct aie_error *errs = err_info;
	enum xrt_error_module xrt_err_mod;
	enum xrt_error_num err_num;
	struct aie_error *err;
	u64 err_code;

	/* Cache the last async error only */
	err = &errs[num_err - 1];
	err_num = aie_err_cat_get_xrt_err_num(aie_get_error_category(err->row, err->event_id,
								     err->mod_type));
	xrt_err_mod = aie_get_xrt_error_mod(err->mod_type);
	err_code = XRT_ERROR_CODE_BUILD(err_num, XRT_ERROR_DRIVER_AIE,
					XRT_ERROR_SEVERITY_CRITICAL, xrt_err_mod,
					XRT_ERROR_CLASS_AIE);

	mutex_lock(&ndev->async_errs_cache.lock);
	record->ts_us = current_time_us;
	record->err_code = err_code;
	mutex_unlock(&ndev->async_errs_cache.lock);
}

static u32 aie2_error_backtrack(struct amdxdna_dev_hdl *ndev, void *err_info, u32 num_err)
{
	struct aie_error *errs = err_info;
	u32 err_col = 0; /* assume that AIE has less than 32 columns */
	int i;

	/* Get err column bitmap */
	for (i = 0; i < num_err; i++) {
		struct aie_error *err = &errs[i];
		enum aie_error_category cat;

		cat = aie_get_error_category(err->row, err->event_id, err->mod_type);
		XDNA_ERR(ndev->xdna, "Row: %d, Col: %d, module %d, event ID %d, category %d",
			 err->row, err->col, err->mod_type,
			 err->event_id, cat);

		if (err->col >= 32) {
			/* If you see this, contact NPU firmware team */
			XDNA_WARN(ndev->xdna, "Device has more than 32 columns?");
			break;
		}

		err_col |= (1 << err->col);
	}

	return err_col;
}

static int aie2_error_async_cb(void *handle, void __iomem *data, size_t size)
{
	struct async_event *e = handle;

	if (data) {
		e->resp.type = readl(data + offsetof(struct async_event_msg_resp, type));
		wmb(); /* Update status in the end, so that no lock for here */
		e->resp.status = readl(data + offsetof(struct async_event_msg_resp, status));
	}
	queue_work(e->wq, &e->work);
	return 0;
}

static int aie2_error_event_send(struct async_event *e)
{
	aie2_mgmt_buff_clflush(&e->mgmt_hdl);
	return aie2_register_asyn_event_msg(e->ndev, &e->mgmt_hdl, e, aie2_error_async_cb);
}

static void aie2_error_worker(struct work_struct *err_work)
{
	struct aie_err_info *info;
	struct amdxdna_dev *xdna;
	struct async_event *e;
	void *vaddr;
	u32 max_err;
	u32 err_col;

	e = container_of(err_work, struct async_event, work);

	xdna = e->ndev->xdna;

	if (e->resp.status == MAX_AIE2_STATUS_CODE)
		return;

	e->resp.status = MAX_AIE2_STATUS_CODE;

	vaddr = aie2_mgmt_buff_get_cpu_addr(&e->mgmt_hdl);
	if (IS_ERR(vaddr)) {
		XDNA_ERR(xdna, "Failed to get a valid virtual addr: %ld", PTR_ERR(vaddr));
		return;
	}

	print_hex_dump_debug("AIE error: ", DUMP_PREFIX_OFFSET, 16, 4, vaddr, 0x100, false);

	info = (struct aie_err_info *)vaddr;
	XDNA_DBG(xdna, "Error count %d return code %d", info->err_cnt, info->ret_code);

	max_err = (ASYNC_BUF_SIZE - sizeof(*info)) / sizeof(struct aie_error);
	if (unlikely(info->err_cnt > max_err)) {
		WARN_ONCE(1, "Error count too large %d\n", info->err_cnt);
		return;
	}
	err_col = aie2_error_backtrack(e->ndev, info->payload, info->err_cnt);
	if (!err_col) {
		XDNA_WARN(xdna, "Did not get error column");
		return;
	}

	aie2_async_errors_cache(e->ndev, info->payload, info->err_cnt);

	mutex_lock(&xdna->dev_handle->aie2_lock);
	/* Re-sent this event to firmware */
	if (aie2_error_event_send(e))
		XDNA_WARN(xdna, "Unable to register async event");
	mutex_unlock(&xdna->dev_handle->aie2_lock);
}

void aie2_error_async_events_free(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct async_events *events;
	int i;

	drm_WARN_ON(&xdna->ddev, mutex_is_locked(&ndev->aie2_lock));
	events = ndev->async_events;
	destroy_workqueue(events->wq);

	for (i = 0; i < events->event_cnt; i++) {
		struct async_event *e = &events->event[i];

		aie2_mgmt_buff_free(&e->mgmt_hdl);
	}
	kfree(events);
}

int aie2_error_async_events_alloc(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct async_events *events;
	struct async_event *e;
	int i, ret;

	events = kzalloc(struct_size(events, event, ndev->total_col), GFP_KERNEL);
	if (!events)
		return -ENOMEM;

	events->event_cnt = ndev->total_col;
	events->wq = alloc_ordered_workqueue("async_wq", 0);
	if (!events->wq) {
		ret = -ENOMEM;
		goto free_events;
	}

	for (i = 0; i < events->event_cnt; i++) {
		struct async_event *e = &events->event[i];
		struct aie2_mgmt_dma_hdl *mgmt_hdl = &e->mgmt_hdl;
		void *buf;

		buf = aie2_mgmt_buff_alloc(ndev, mgmt_hdl, ASYNC_BUF_SIZE, DMA_FROM_DEVICE);
		if (!buf) {
			ret = -ENOMEM;
			goto free_buf;
		}

		e->ndev = ndev;
		e->wq = events->wq;
		e->resp.status = MAX_AIE2_STATUS_CODE;
		INIT_WORK(&e->work, aie2_error_worker);
	}

	ndev->async_events = events;

	for (i = 0; i < ndev->async_events->event_cnt; i++) {
		e = &ndev->async_events->event[i];
		ret = aie2_error_event_send(e);
		if (ret)
			goto free_buf;
	}

	/* Just to make sure firmware handled async events */
	ret = aie2_query_aie_firmware_version(ndev, &ndev->xdna->fw_ver);
	if (ret) {
		XDNA_ERR(xdna, "Re-query firmware version failed");
		goto free_buf;
	}

	XDNA_DBG(xdna, "Async event count %d, buf total size 0x%x",
		 events->event_cnt, ASYNC_BUF_SIZE);
	return 0;

free_buf:
	while (i) {
		struct async_event *e = &events->event[i - 1];

		aie2_mgmt_buff_free(&e->mgmt_hdl);
		--i;
	}
	destroy_workqueue(events->wq);
free_events:
	kfree(events);
	return ret;
}

/**
 * amdxdna_error_async_cache_init - Initialize async error cache
 * @ndev: XDNA device handle for async errors cache initialization
 * Return: 0 for success.
 */
int aie2_error_async_cache_init(struct amdxdna_dev_hdl *ndev)
{
	return amdxdna_error_async_cache_init(&ndev->async_errs_cache);
}

/**
 * amdxdna_aie2_get_last_async_error - Retrieve the last asynchronous error information.
 * @xdna: Pointer to the xdna structure.
 * @num_errs: in/out, Number of error structures to populate.
 * @errors_ret: async errors information array to return
 *
 * This function obtains the most recent asynchronous error that occurred
 * in the AIE2 subsystem and populates the provided error information structure.
 * It is typically used for error handling and diagnostics in the driver.
 * Today, only one last async error is cached. And thus, this function will only
 * return 1 last async error.
 *
 * Return: 0 on success, negative error code on failure.
 */
int aie2_error_get_last_async(struct amdxdna_dev *xdna, u32 num_errs, void *errors_ret)
{
	return amdxdna_error_get_last_async(xdna, &xdna->dev_handle->async_errs_cache, num_errs,
										errors_ret);
}
