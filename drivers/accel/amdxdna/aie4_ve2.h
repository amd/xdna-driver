/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AIE4_VE2_H_
#define _AIE4_VE2_H_

struct amdxdna_dev_ops;
struct amdxdna_hwctx;
struct mailbox;

extern const struct amdxdna_dev_ops aie4_ve2_ops;

void ve2_mbox_release(struct mailbox *mb);
int ve2_mbox_load_fw(struct mailbox *mb);
int ve2_cert_bind(struct amdxdna_hwctx *hwctx);
int ve2_cert_kick(struct amdxdna_hwctx *hwctx);

#endif /* _AIE4_VE2_H_ */
