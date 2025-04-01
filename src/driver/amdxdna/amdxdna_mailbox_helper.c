// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "amdxdna_mailbox_helper.h"

int xdna_msg_dummy_cb(void *handle, void __iomem *data, size_t size)
{
	struct amdxdna_dev *xdna = handle;
	u32 status;

	if (data)
		memcpy_fromio(&status, data, sizeof(status));

	XDNA_DBG(xdna, "Got dummy resp, status 0x%x", status);
	return 0;
}

int xdna_msg_cb(void *handle, void __iomem *data, size_t size)
{
	struct xdna_notify *cb_arg = handle;
	int ret;

	if (unlikely(!data))
		goto out;

	if (unlikely(cb_arg->size != size)) {
		cb_arg->error = -EINVAL;
		goto out;
	}

	memcpy_fromio(cb_arg->data, data, cb_arg->size);
	print_hex_dump_debug("resp data: ", DUMP_PREFIX_OFFSET,
			     16, 4, cb_arg->data, cb_arg->size, true);
out:
	ret = cb_arg->error;
	complete(&cb_arg->comp);
	return ret;
}

int xdna_send_msg_wait(struct amdxdna_dev *xdna, struct mailbox_channel *chann,
		       struct xdna_mailbox_msg *msg)
{
	struct xdna_notify *hdl = msg->handle;
	int ret;

	ret = xdna_mailbox_send_msg(chann, msg, TX_TIMEOUT);
	if (ret) {
		XDNA_ERR(xdna, "Send message failed, ret %d", ret);
		return ret;
	}

	ret = wait_for_completion_timeout(&hdl->comp,
					  msecs_to_jiffies(RX_TIMEOUT));
	if (!ret) {
		XDNA_ERR(xdna, "Wait for completion timeout");
		return -ETIME;
	}

	return hdl->error;
}
