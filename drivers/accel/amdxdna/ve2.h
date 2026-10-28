/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _VE2_H_
#define _VE2_H_

#include <linux/types.h>

struct amdxdna_dev_ops;
struct mailbox;

extern const struct amdxdna_dev_ops ve2_ops;

void ve2_mbox_release(struct mailbox *mb);
int ve2_mbox_load_fw(struct mailbox *mb);
int ve2_mbox_attach_notify(struct mailbox *mb, u32 index, void (*cb)(void *data),
			   void *data);
void ve2_mbox_detach_notify(struct mailbox *mb, u32 index);
int ve2_mbox_ring_doorbell(struct mailbox *mb, u32 hw_ctx_id);

#endif /* _VE2_H_ */
