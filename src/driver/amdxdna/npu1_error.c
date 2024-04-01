// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include <linux/kthread.h>
#include <linux/kernel.h>
#include "npu1_msg_priv.h"
#include "npu1_pci.h"

#define AIE_ERROR_SIZE 0x3000

/*
 * This is porting from XAIE util header file.
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
	enum aie_module_type mod_type;
	u8			event_id;
};

struct aie_event_category {
	enum aie_error_category category;
	u8			event_id;
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

static u32 npu1_error_backtrack(struct npu_device *ndev, void *err_info, u32 num_err)
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

		err_col |= (1 << err->col);
	}

	/* TODO: Send AIE error to EDAC system */

	return err_col;
}

static void npu1_error_process(struct npu_device *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	u32 row = 0, col = 0, mod = 0;
	dma_addr_t fw_addr;
	void *async_buf;
	u32 err_col;
	u32 count;
	bool next;
	int ret;

	async_buf = dma_alloc_coherent(xdna->ddev.dev, AIE_ERROR_SIZE, &fw_addr, GFP_KERNEL);
	if (!async_buf)
		return;

	do {
		struct amdxdna_client *client;

		ret = npu1_query_error(ndev, fw_addr, AIE_ERROR_SIZE,
				       &row, &col, &mod, &count, &next);
		if (ret) {
			XDNA_ERR(xdna, "query AIE error, ret %d", ret);
			break;
		}

		print_hex_dump_debug("AIE error: ", DUMP_PREFIX_OFFSET, 16, 4, async_buf,
				     sizeof(struct aie_error) * count, true);

		if (!count) {
			XDNA_WARN(xdna, "Spurious row %d, col %d, mod %d, count %d, next %d",
				  row, col, mod, count, next);
			continue;
		}

		err_col = npu1_error_backtrack(ndev, async_buf, count);
		if (!err_col) {
			XDNA_WARN(xdna, "Did not get error column");
			continue;
		}

		/* found error columns, let's start recovery */
		mutex_lock(&xdna->dev_lock);
		list_for_each_entry(client, &xdna->client_list, node)
			npu1_stop_ctx_by_col_map(client, err_col);

		/*
		 * The error columns will be reset after all hardware
		 * contexts which use these columns are destroyed.
		 * So try to restart the hardware contexts.
		 */
		list_for_each_entry(client, &xdna->client_list, node)
			npu1_restart_ctx(client);

		mutex_unlock(&xdna->dev_lock);
	} while (next);

	dma_free_coherent(xdna->ddev.dev, AIE_ERROR_SIZE, async_buf, fw_addr);
}

int npu1_error_async_msg_thread(void *data)
{
	struct amdxdna_dev *xdna = (struct amdxdna_dev *)data;
	struct xdna_mailbox_async amsg = { 0 };
	int ret = 0;

	XDNA_DBG(xdna, "start...");
	while (!kthread_should_stop()) {
		memset(&amsg, 0, sizeof(amsg));
		ret = xdna_mailbox_wait_async_msg(xdna->dev_handle->mgmt_chann, &amsg, true);
		if (ret == -EAGAIN)
			continue;

		if (ret == -ERESTARTSYS)
			break;

		if (amsg.opcode != MSG_OP_ASYNC_MSG_AIE_ERROR) {
			XDNA_ERR(xdna, "Unknown ASYNC message op(0x%x)", amsg.opcode);
			continue;
		}

		npu1_error_process(xdna->dev_handle);
	}
	XDNA_DBG(xdna, "stop...");

	return ret;
}
