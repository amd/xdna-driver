/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Platform-only extension to the transport-neutral mailbox interface
 * (amdxdna_mailbox.h).  The shmem+IPI transport in amdxdna_mailbox_plat.c
 * implements struct mailbox and the standard mailbox API for the platform build
 * (mutually exclusive with the PCI amdxdna_mailbox.c).  The hw_ctx dispatch
 * doorbell is not part of that neutral API, so it is exposed here for the aie4
 * doorbell hook to ring.
 */

#ifndef _AMDXDNA_MAILBOX_PLAT_H_
#define _AMDXDNA_MAILBOX_PLAT_H_

#include <linux/types.h>

struct mailbox;

/* Ring the hw_ctx dispatch doorbell (shmem produce + IPI kick). */
int amdxdna_mailbox_plat_ring_doorbell(struct mailbox *mb, u32 hw_ctx_id);

#endif /* _AMDXDNA_MAILBOX_PLAT_H_ */
