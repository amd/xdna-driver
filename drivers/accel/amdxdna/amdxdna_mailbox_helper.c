// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_device.h>
#include <drm/drm_print.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/gpu_scheduler.h>
#include <linux/completion.h>

#include "amdxdna_gem.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_mailbox_helper.h"
#include "amdxdna_drv.h"

int xdna_msg_cb(void *handle, void __iomem *data, size_t size)
{
	struct xdna_notify *cb_arg = handle;
	int ret;

	/*
	 * A NULL handle means no sender is waiting on this message -- there is
	 * nothing to complete and nowhere to store a response. Under the
	 * current design every sender path either holds a valid handle or
	 * sends fire-and-forget with handle == NULL by construction; this
	 * guard catches the second case on channel teardown. Log loudly if a
	 * response actually arrived (data != NULL): that would mean a synchronous
	 * sender bookkeeping invariant has broken.
	 */
	if (unlikely(!cb_arg)) {
		if (data)
			pr_err_ratelimited("Mailbox response dropped: no waiter for message\n");
		return 0;
	}

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
		/*
		 * Firmware is reported to complete some commands, SUSPEND in
		 * particular, by writing the response into the ring buffer
		 * without raising the completion interrupt, so nothing wakes
		 * the receive path and the wait above expires on a command that
		 * did finish. Drain the ring by hand before declaring the
		 * command lost; this also picks up a response that landed in
		 * the instant the wait was timing out.
		 */
		xdna_mailbox_drain_channel(chann);
		if (!try_wait_for_completion(&hdl->comp)) {
			XDNA_ERR(xdna, "Wait for completion timeout");
			return -ETIME;
		}
		XDNA_DBG(xdna,
			 "Opcode 0x%x completed without an interrupt, response taken from the ring buffer",
			 msg->opcode);
	}

	return hdl->error;
}
