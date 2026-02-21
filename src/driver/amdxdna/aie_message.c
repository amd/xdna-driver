// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm_local/amdxdna_accel.h"

#include "amdxdna_pci_drv.h"
#include "aie_message.h"

int aie_send_msg_wait(struct amdxdna_dev *xdna,
		      struct mailbox_channel **chann,
		      struct xdna_mailbox_msg *msg)
{
	struct xdna_notify *hdl = msg->handle;
	int ret;

	if (!(*chann))
		return -ENODEV;

	ret = xdna_send_msg_wait(xdna, *chann, msg);
	if (ret == -ETIME) {
		xdna_mailbox_stop_channel(*chann);
		xdna_mailbox_destroy_channel(*chann);
		*chann = NULL;
	}

	if (!ret && *hdl->status) {
		XDNA_ERR(xdna, "command opcode 0x%x failed, status 0x%x",
			 msg->opcode, *hdl->status);
		ret = -EINVAL;
	}

	return ret;
}

