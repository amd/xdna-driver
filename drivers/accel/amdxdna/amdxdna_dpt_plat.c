// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Platform transport completion notification for DPT. The platform device has
 * no PCI MSI-X vector to request, so there is no interrupt backend here: the
 * firmware publishes DPT completions into a DRAM ring that the common DPT layer
 * drains on demand. No notification setup is needed, so this is a successful
 * no-op; it mirrors amdxdna_dpt_pci.c without pulling in the PCI-only
 * to_pci_dev() / pci_irq_vector() calls, which are invalid for a platform
 * device.
 */

#include "amdxdna_dpt.h"

int amdxdna_dpt_notification_init(struct amdxdna_dpt *dpt)
{
	/*
	 * No MSI-X on the platform transport and nothing to wire up; the DPT
	 * layer polls the ring on demand.  Report success -- there is no
	 * notification to fail, so this must not fail DPT init.
	 */
	return 0;
}

void amdxdna_dpt_notification_fini(struct amdxdna_dpt *dpt)
{
}
