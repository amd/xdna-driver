// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * PCI transport completion notification for DPT. Interrupt delivery is
 * firmware-dependent and may be unavailable: when firmware supports it, it wakes
 * the host via an MSI-X vector whose payload address/index it reports at ring
 * setup (io_base + msi_address / msi_idx, filled by aie4_pci.c); the handler acks
 * the MSI write and kicks the deferred worker, and the ring drain itself lives in
 * amdxdna_dpt.c.
 *
 * When firmware reports no vector (msi_idx / msi_address stay zero, as the AIE4
 * fallback does), amdxdna_dpt_notification_init() returns -EINVAL and the DPT
 * layer relies on timer-based polling instead.
 */

#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/workqueue.h>

#include "amdxdna_dpt.h"
#include "amdxdna_drv.h"

static irqreturn_t amdxdna_dpt_irq_handler(int irq, void *data)
{
	struct amdxdna_dpt *dpt = data;

	if (dpt->io_base)
		writel(0, dpt->io_base + dpt->msi_address);

	queue_work(system_percpu_wq, &dpt->work);
	return IRQ_HANDLED;
}

int amdxdna_dpt_notification_init(struct amdxdna_dpt *dpt)
{
	struct amdxdna_dev *xdna = dpt->xdna;
	int ret;

	if (!dpt->msi_idx || !dpt->msi_address)
		return -EINVAL;

	ret = pci_irq_vector(to_pci_dev(xdna->ddev.dev), dpt->msi_idx);
	if (ret < 0) {
		dpt->irq = 0;
		return ret;
	}
	dpt->irq = ret;

	ret = request_irq(dpt->irq, amdxdna_dpt_irq_handler, 0,
			  amdxdna_dpt_irq_name(dpt), dpt);
	if (ret) {
		dpt->irq = 0;
		return ret;
	}

	return 0;
}

void amdxdna_dpt_notification_fini(struct amdxdna_dpt *dpt)
{
	if (dpt->irq) {
		free_irq(dpt->irq, dpt);
		dpt->irq = 0;
	}
	dpt->msi_address = 0;
	dpt->msi_idx = 0;
}
