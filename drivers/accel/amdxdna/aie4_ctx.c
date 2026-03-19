// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_device.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_print.h>
#include <drm/gpu_scheduler.h>
#include <linux/types.h>

#include "aie.h"
#include "aie4_host_queue.h"
#include "aie4_pci.h"
#include "aie4_msg_priv.h"
#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_mailbox_helper.h"
#include "amdxdna_pci_drv.h"

static irqreturn_t cert_comp_isr(int irq, void *p)
{
	struct cert_comp *cert_comp = p;

	wake_up_all(&cert_comp->waitq);
	return IRQ_HANDLED;
}

static struct cert_comp *aie4_lookup_cert_comp(struct amdxdna_dev_hdl *ndev, u32 msix_idx)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct cert_comp *cert_comp;
	int ret;

	guard(mutex)(&ndev->cert_comp_lock);

	cert_comp = xa_load(&ndev->cert_comp_xa, msix_idx);
	if (cert_comp) {
		kref_get(&cert_comp->kref);
		return cert_comp;
	}

	cert_comp = kzalloc_obj(*cert_comp);
	if (!cert_comp)
		return NULL;

	cert_comp->ndev = ndev;
	cert_comp->msix_idx = msix_idx;
	cert_comp->irq = -ENOENT;
	init_waitqueue_head(&cert_comp->waitq);
	kref_init(&cert_comp->kref);

	ret = pci_irq_vector(pdev, cert_comp->msix_idx);
	if (ret < 0) {
		XDNA_ERR(xdna, "MSI-X idx %u is invalid, ret:%d", msix_idx, ret);
		goto free_cert_comp;
	}
	cert_comp->irq = ret;

	ret = request_irq(cert_comp->irq, cert_comp_isr, 0, "xdna_hsa", cert_comp);
	if (ret) {
		XDNA_ERR(xdna, "request irq %d failed %d", cert_comp->irq, ret);
		cert_comp->irq = -ENOENT;
		goto free_cert_comp;
	}

	ret = xa_err(xa_store(&ndev->cert_comp_xa, msix_idx, cert_comp, GFP_KERNEL));
	if (ret) {
		XDNA_ERR(xdna, "store cert_comp for msix idx %d failed %d", msix_idx, ret);
		goto free_irq;
	}

	return cert_comp;

free_irq:
	free_irq(cert_comp->irq, cert_comp);
free_cert_comp:
	kfree(cert_comp);
	return NULL;
}

static void cert_comp_release(struct kref *kref)
{
	struct cert_comp *cert_comp = container_of(kref, struct cert_comp, kref);
	struct amdxdna_dev_hdl *ndev = cert_comp->ndev;

	drm_WARN_ON(&ndev->aie.xdna->ddev, !mutex_is_locked(&ndev->cert_comp_lock));

	xa_erase(&ndev->cert_comp_xa, cert_comp->msix_idx);
	if (cert_comp->irq >= 0)
		free_irq(cert_comp->irq, cert_comp);
	kfree(cert_comp);
}

static void aie4_put_cert_comp(struct cert_comp *cert_comp)
{
	struct amdxdna_dev_hdl *ndev;

	if (!cert_comp)
		return;

	ndev = cert_comp->ndev;
	guard(mutex)(&ndev->cert_comp_lock);
	kref_put(&cert_comp->kref, cert_comp_release);
}

static int aie4_msg_destroy_context(struct amdxdna_dev_hdl *ndev, u32 hw_context_id)
{
	DECLARE_AIE_MSG(aie4_msg_destroy_hw_context, AIE4_MSG_OP_DESTROY_HW_CONTEXT);

	req.hw_context_id = hw_context_id;
	return aie_send_mgmt_msg_wait(&ndev->aie, &msg);
}

static int aie4_hwctx_create(struct amdxdna_hwctx *hwctx)
{
	DECLARE_AIE_MSG(aie4_msg_create_hw_context, AIE4_MSG_OP_CREATE_HW_CONTEXT);
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!ndev->partition_id || !hwctx->num_tiles) {
		XDNA_ERR(xdna, "invalid request partition_id %d, num_tiles %d",
			 ndev->partition_id, hwctx->num_tiles);
		return -EINVAL;
	}

	req.partition_id = ndev->partition_id;
	req.request_num_tiles = hwctx->num_tiles;
	req.pasid = FIELD_PREP(AIE4_MSG_PASID, client->pasid) |
		FIELD_PREP(AIE4_MSG_PASID_VLD, 1);
	req.priority_band = hwctx->qos.priority;

	req.hsa_addr_high = upper_32_bits(amdxdna_gem_dev_addr(priv->umq_bo));
	req.hsa_addr_low = lower_32_bits(amdxdna_gem_dev_addr(priv->umq_bo));

	XDNA_DBG(xdna, "pasid 0x%x, num_tiles %d, hsa[0x%x 0x%x]",
		 req.pasid, req.request_num_tiles, req.hsa_addr_high, req.hsa_addr_low);

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret) {
		XDNA_ERR(xdna, "create ctx failed: %d", ret);
		return ret;
	}

	XDNA_DBG(xdna, "resp msix: %d, ctx id: %d, doorbell: %d",
		 resp.job_complete_msix_idx,
		 resp.hw_context_id,
		 resp.doorbell_offset);

	/* setup interrupt completion per msix index */
	priv->cert_comp = aie4_lookup_cert_comp(ndev, resp.job_complete_msix_idx);
	if (!priv->cert_comp) {
		aie4_msg_destroy_context(ndev, resp.hw_context_id);
		return -EINVAL;
	}

	priv->hw_ctx_id = resp.hw_context_id;
	hwctx->doorbell_offset = resp.doorbell_offset;

	return 0;
}

static void aie4_hwctx_destroy(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	aie4_msg_destroy_context(ndev, priv->hw_ctx_id);
	aie4_put_cert_comp(priv->cert_comp);
}

static void aie4_hwctx_umq_fini(struct amdxdna_hwctx *hwctx)
{
	if (hwctx->priv && hwctx->priv->umq_bo)
		drm_gem_object_put(to_gobj(hwctx->priv->umq_bo));
}

static int aie4_hwctx_umq_init(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_gem_obj *umq_bo;
	struct host_queue_header *qhdr;

	umq_bo = amdxdna_gem_get_obj(hwctx->client, hwctx->umq_bo_hdl, AMDXDNA_BO_SHARE);
	if (!umq_bo) {
		XDNA_ERR(xdna, "cannot find umq_bo handle %d", hwctx->umq_bo_hdl);
		return -ENOENT;
	}
	if (umq_bo->mem.size < sizeof(*qhdr)) {
		XDNA_ERR(xdna, "umq_bo size is too small");
		return -EINVAL;
	}

	priv->umq_bo = umq_bo;
	/* get kva address for host queue read index and write index */
	qhdr = amdxdna_gem_vmap(umq_bo);
	if (!qhdr) {
		aie4_hwctx_umq_fini(hwctx);
		return -ENOMEM;
	}

	priv->umq_read_index = &qhdr->read_index;
	priv->umq_write_index = &qhdr->write_index;

	return 0;
}

int aie4_hwctx_init(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx_priv *priv;
	int ret;

	priv = kzalloc_obj(*priv);
	if (!priv)
		return -ENOMEM;
	hwctx->priv = priv;

	ret = aie4_hwctx_umq_init(hwctx);
	if (ret)
		goto free_priv;

	ret = aie4_hwctx_create(hwctx);
	if (ret)
		goto umq_fini;

	XDNA_DBG(xdna, "hwctx %s init completed", hwctx->name);
	return 0;

umq_fini:
	aie4_hwctx_umq_fini(hwctx);
free_priv:
	kfree(priv);
	hwctx->priv = NULL;
	return ret;
}

void aie4_hwctx_fini(struct amdxdna_hwctx *hwctx)
{
	aie4_hwctx_destroy(hwctx);
	aie4_hwctx_umq_fini(hwctx);
	kfree(hwctx->priv);
}
