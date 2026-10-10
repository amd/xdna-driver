/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _VE2_H_
#define _VE2_H_

struct amdxdna_dev_ops;
struct mailbox;

extern const struct amdxdna_dev_ops ve2_ops;

void ve2_mbox_release(struct mailbox *mb);
int ve2_mbox_load_fw(struct mailbox *mb);

#endif /* _VE2_H_ */
