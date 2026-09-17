/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Platform-only extension to the transport-neutral mailbox interface
 * (amdxdna_mailbox.h).  The shared memory + IPI transport in
 * amdxdna_mailbox_plat.c implements struct mailbox and the standard mailbox API
 * for the platform build (mutually exclusive with the PCI amdxdna_mailbox.c).
 * The hw_ctx dispatch doorbell and the cert-completion registry are not part of
 * that neutral API, so they are exposed here for the aie4 transport hooks to
 * use.
 */

#ifndef _AMDXDNA_MAILBOX_PLAT_H_
#define _AMDXDNA_MAILBOX_PLAT_H_

#include <linux/types.h>

struct cert_comp;
struct mailbox;

/* Ring the hw_ctx dispatch doorbell (shared-memory produce + IPI kick). */
int amdxdna_mailbox_plat_ring_doorbell(struct mailbox *mb, u32 hw_ctx_id);

/*
 * Add/remove a cert completion from the shared completion-IPI fan-out.  The
 * unregister serialises against an in-flight fan-out, so it is safe to free the
 * cert_comp once it returns.
 */
int amdxdna_mailbox_plat_register_notify(struct mailbox *mb, u32 msix_idx,
					 struct cert_comp *comp);
void amdxdna_mailbox_plat_unregister_notify(struct mailbox *mb, u32 msix_idx);

#endif /* _AMDXDNA_MAILBOX_PLAT_H_ */
