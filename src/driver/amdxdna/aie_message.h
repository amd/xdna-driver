// SPDX-License-Identifier: GPL-2.0 
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */
#ifndef _AIE_MSG_H_
#define _AIE_MSG_H_

#include "amdxdna_mailbox.h"
#include "amdxdna_mailbox_helper.h"

#define DECLARE_AIE_MSG(name, op) DECLARE_XDNA_MSG_COMMON(name, op, -1)

int aie_send_msg_wait(struct amdxdna_dev *xdna,
		      struct mailbox_channel **chann,
		      struct xdna_mailbox_msg *msg);

#endif /* _AIE_MSG_H_ */

