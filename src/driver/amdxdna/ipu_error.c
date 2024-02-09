// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 *
 * Authors:
 *	Min Ma <min.ma@amd.com>
 */

#include <linux/kthread.h>
#include "amdxdna_drv.h"
#include "ipu_common.h"
#include "ipu_msg_priv.h"
#include "amdxdna_util.h"
#include "ipu_error.h"
#include "ipu_pci.h"

#define AIE_ERROR_SIZE 0x3000

static u32 ipu_error_backtrack(struct ipu_device *idev, void *err_info, u32 num_err)
{
	struct aie_error *errs = err_info;
	u32 err_col = 0; /* assume that AIE has less than 32 columns */
	int i;

	/* Get err column bitmap */
	for (i = 0; i < num_err; i++) {
		struct aie_error *err = &errs[i];
		enum aie_error_category cat;

		cat = aie_get_error_category(err->row, err->event_id, err->mod_type);
		XDNA_ERR(idev->xdna, "Row: %d, Col: %d, module %d, event ID %d, category %d",
			 err->row, err->col, err->mod_type,
			 err->event_id, cat);

		err_col |= (1 << err->col);
	}

	/* TODO: Send AIE error to EDAC system */

	return err_col;
}

static void ipu_error_process(struct ipu_device *idev)
{
	struct amdxdna_dev *xdna = idev->xdna;
	u32 row = 0, col = 0, mod = 0;
	dma_addr_t fw_addr;
	void *async_buf;
	u32 err_col;
	u32 count;
	bool next;
	int ret;

	async_buf = dma_alloc_coherent(&xdna->pdev->dev, AIE_ERROR_SIZE, &fw_addr, GFP_KERNEL);
	if (!async_buf)
		return;

	do {
		struct amdxdna_client *client;

		ret = ipu_query_error(idev, fw_addr, AIE_ERROR_SIZE,
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

		err_col = ipu_error_backtrack(idev, async_buf, count);
		if (!err_col) {
			XDNA_WARN(xdna, "Did not get error column");
			continue;
		}

		/* found error columns, let's start recovery */
		mutex_lock(&xdna->dev_lock);
		list_for_each_entry(client, &xdna->client_list, node)
			amdxdna_stop_ctx_by_col_map(client, err_col);

		/*
		 * The error columns will be reset after all hardware
		 * contexts which use these columns are destroyed.
		 * So try to restart the hardware contexts.
		 */
		list_for_each_entry(client, &xdna->client_list, node)
			amdxdna_restart_ctx(client);

		mutex_unlock(&xdna->dev_lock);
	} while (next);

	dma_free_coherent(&xdna->pdev->dev, AIE_ERROR_SIZE, async_buf, fw_addr);
}

int ipu_error_async_msg_thread(void *data)
{
	struct amdxdna_dev *xdna = (struct amdxdna_dev *)data;
	struct xdna_mailbox_async amsg = { 0 };
	int ret = 0;

	XDNA_DBG(xdna, "start...");
	while (!kthread_should_stop()) {
		memset(&amsg, 0, sizeof(amsg));
		ret = xdna_mailbox_wait_async_msg(xdna->mgmt_chann, &amsg, true);
		if (ret == -EAGAIN)
			continue;

		if (ret == -ERESTARTSYS)
			break;

		if (amsg.opcode != MSG_OP_ASYNC_MSG_AIE_ERROR) {
			XDNA_ERR(xdna, "Unknown ASYNC message op(0x%x)", amsg.opcode);
			continue;
		}

		/* FIXME: if error happen, mark board as bad status */
		ipu_error_process(xdna->dev_handle);
	}
	XDNA_DBG(xdna, "stop...");

	return ret;
}
