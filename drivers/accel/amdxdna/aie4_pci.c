// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_cache.h>
#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <drm/drm_print.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/sizes.h>
#include <linux/pm_runtime.h>

#include "aie.h"
#include "amdxdna_coredump.h"
#include "amdxdna_ctx_status.h"
#include "amdxdna_tile_read_write.h"
#include "aie4_pci.h"
#include "aie4_msg_priv.h"
#include "amdxdna_ctx.h"
#include "amdxdna_dpt.h"
#include "amdxdna_gem.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_mailbox_helper.h"
#include "amdxdna_drv.h"
#include "amdxdna_pm.h"
#include "amdxdna_sensors.h"
#include "trace/events/amdxdna.h"

#define NO_IOHUB		0
#define CERTFW_MAX_SIZE         (SZ_32K + SZ_256)
#define PSP_NOTIFY_INTR		0xD007BE11

/* Not upstreamed: echo a bypass magic to FW right after work-buffer attach for npu3a. */
#ifdef AMDXDNA_NPU3A
#define AIE4_MSG_OP_ECHO	0x10001
#define MAKE_MAGIC(a, b, c, d)	((u32)((a) << 24 | (b) << 16 | (c) << 8 | (d)))

struct aie4_msg_echo_req {
	u32 val1;
	u32 val2;
} __packed;

struct aie4_msg_echo_resp {
	enum aie4_msg_status status;
	u32 val1;
	u32 val2;
} __packed;

static int aie4_iommu_bypass_echo(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE_MSG(aie4_msg_echo, AIE4_MSG_OP_ECHO);
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret;

	req.val1 = MAKE_MAGIC('B', 'Y', 'P', 'A');
	req.val2 = MAKE_MAGIC('M', 'A', 'G', 'C');

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret) {
		XDNA_ERR(xdna, "iommu bypass echo failed, ret %d", ret);
		return ret;
	}

	if (resp.val1 != req.val1 || resp.val2 != req.val2) {
		XDNA_ERR(xdna, "iommu bypass echo bad value 0x%x 0x%x",
			 resp.val1, resp.val2);
		return -EIO;
	}

	XDNA_INFO(xdna, "iommu bypass echo ok");

	return 0;
}
#endif /* AMDXDNA_NPU3A */

/*
 * The management mailbox channel is allocated by firmware.
 * The related register and ring buffer information is on SRAM BAR.
 * This struct is the register layout.
 */
struct mailbox_info {
	__u32 valid;
	__u32 protocol_major;
	__u32 protocol_minor;
	__u32 x2i_tail_offset;
	__u32 x2i_head_offset;
	__u32 x2i_buffer_addr;
	__u32 x2i_buffer_size;
	__u32 i2x_tail_offset;
	__u32 i2x_head_offset;
	__u32 i2x_buffer_addr;
	__u32 i2x_buffer_size;
	__u32 i2x_msi_idx;
	__u32 reserved[4];
};

static void aie4_fw_clear_alive(struct amdxdna_dev *xdna)
{
	const struct amdxdna_dev_priv *npriv = xdna->dev_info->dev_priv;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	void __iomem *src;

	src = ndev->rbuf_base + npriv->mbox_info_off;
	writel(0, src + offsetof(struct mailbox_info, valid));

	XDNA_DBG(xdna, "alive=%u", readl(src + offsetof(struct mailbox_info, valid)));
}

static int aie4_fw_is_alive(struct amdxdna_dev *xdna)
{
	const struct amdxdna_dev_priv *npriv = xdna->dev_info->dev_priv;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	void __iomem *src;
	u32 fw_is_valid;
	int ret;

	src = ndev->rbuf_base + npriv->mbox_info_off;

	ret = readx_poll_timeout(readl, src + offsetof(struct mailbox_info, valid),
				 fw_is_valid, (fw_is_valid == 0x1),
				 AIE_INTERVAL, AIE_TIMEOUT);
	if (ret)
		XDNA_ERR(xdna, "fw_is_valid=%d after %d ms",
			 fw_is_valid, DIV_ROUND_CLOSEST(AIE_TIMEOUT, 1000000));

	return ret;
}

static void aie4_read_mbox_info(struct amdxdna_dev *xdna,
				struct mailbox_info *mbox_info)
{
	const struct amdxdna_dev_priv *npriv = xdna->dev_info->dev_priv;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	u32 *dst = (u32 *)mbox_info;
	u32 __iomem *src;
	int i;

	src = ndev->rbuf_base + npriv->mbox_info_off;

	for (i = 0; i < sizeof(*mbox_info) / sizeof(u32); i++)
		dst[i] = readl(&src[i]);
}

static int aie4_mailbox_info(struct amdxdna_dev *xdna,
			     struct mailbox_info *mbox_info)
{
	struct aie_device *aie = &xdna->dev_handle->aie;
	int ret;

	ret = aie4_fw_is_alive(xdna);
	if (ret)
		return ret;

	aie4_read_mbox_info(xdna, mbox_info);

	aie->fw_prot_major = mbox_info->protocol_major;
	aie->fw_prot_minor = mbox_info->protocol_minor;

	ret = aie_check_protocol(aie);
	if (ret)
		XDNA_ERR(xdna, "mailbox major.minor %d.%d is not supported",
			 mbox_info->protocol_major, mbox_info->protocol_minor);

	return ret;
}

static void aie4_mailbox_fini(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;

	aie_destroy_chann(&ndev->aie, &ndev->aie.mgmt_chann);
	drmm_kfree(&xdna->ddev, ndev->mbox);
	ndev->mbox = NULL;
}

static irqreturn_t cert_comp_isr(int irq, void *p)
{
	struct cert_comp *cert_comp = p;

	trace_uc_irq_handle("cert", cert_comp->msix_idx);
	wake_up_all(&cert_comp->waitq);
	return IRQ_HANDLED;
}

/*
 * Transport hook: wire the per-cert completion notification.  PCI maps the
 * firmware-provided MSI-X index to a Linux irq and registers cert_comp_isr;
 * the platform build registers an IPI mailbox callback instead.
 */
int aie4_request_notification(struct cert_comp *comp)
{
	struct pci_dev *pdev = to_pci_dev(comp->ndev->aie.xdna->ddev.dev);
	int ret;

	ret = pci_irq_vector(pdev, comp->msix_idx);
	if (ret < 0)
		return ret;
	comp->irq = ret;

	ret = request_irq(comp->irq, cert_comp_isr, 0, "xdna_hsa", comp);
	if (ret) {
		comp->irq = -ENOENT;
		return ret;
	}

	return 0;
}

/* Transport hook: tear down the completion notification wired by the hook above. */
void aie4_free_notification(struct cert_comp *comp)
{
	if (comp->irq >= 0)
		free_irq(comp->irq, comp);
}

/*
 * Transport hook: take what this transport needs from the create-context
 * response.  PCI validates the firmware-provided doorbell offset against the
 * mapped doorbell BAR and stores this context's kick target.  Caller holds
 * io_lock, which also serializes the read in aie4_doorbell_ring(), so plain
 * accesses (no WRITE_ONCE/READ_ONCE) are sufficient.
 */
int aie4_doorbell_setup(struct amdxdna_hwctx *hwctx,
			const struct aie4_msg_create_hw_context_resp *resp)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	u64 db_off = (u64)ndev->priv->doorbell_off + resp->doorbell_offset;

	/*
	 * doorbell_base is a pcim_iomap() of the whole doorbell BAR.  The offset
	 * comes from firmware (or, on a VF, the PF/hypervisor); reject one that
	 * would place the u32 doorbell write past the mapped BAR before
	 * aie4_doorbell_ring() ever dereferences priv->doorbell_addr.  Mirrors the
	 * bounds check on the user mmap path (aie4_doorbell_mmap).
	 */
	if (db_off + sizeof(u32) >
	    pci_resource_len(pdev, xdna->dev_info->doorbell_bar)) {
		XDNA_ERR(xdna, "doorbell offset 0x%llx out of BAR", db_off);
		return -EINVAL;
	}

	priv->doorbell_addr = ndev->doorbell_base + ndev->priv->doorbell_off +
			      resp->doorbell_offset;
	return 0;
}

/* Transport hook: ring this context's doorbell (kick CERT). */
void aie4_doorbell_ring(struct amdxdna_hwctx *hwctx)
{
	writel(0, hwctx->priv->doorbell_addr);
}

static int aie4_irq_init(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret, nvec;

	nvec = pci_msix_vec_count(pdev);
	XDNA_DBG(xdna, "irq vectors:%d", nvec);
	if (nvec <= 0) {
		XDNA_ERR(xdna, "does not get number of interrupt vector");
		return -EINVAL;
	}

	ret = pci_alloc_irq_vectors(pdev, nvec, nvec, PCI_IRQ_MSIX);
	if (ret < 0) {
		XDNA_ERR(xdna, "failed to alloc irq vector, ret: %d", ret);
		return ret;
	}

	return 0;
}

static int aie4_mailbox_start(struct amdxdna_dev *xdna,
			      struct mailbox_info *mbi)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	const struct amdxdna_dev_priv *npriv = xdna->dev_info->dev_priv;
	struct xdna_mailbox_chann_res *i2x;
	struct xdna_mailbox_chann_res *x2i;
	int mgmt_mb_irq;
	int ret;

	struct xdna_mailbox_res mbox_res = {
		.ringbuf_base = ndev->rbuf_base,
		.ringbuf_size = pci_resource_len(pdev, npriv->mbox_rbuf_bar),
		.mbox_base = ndev->mbox_base,
		.mbox_size = pci_resource_len(pdev, npriv->mbox_bar),
		.name = "xdna_aie4_mailbox",
	};

	i2x = &ndev->aie.mgmt_i2x;
	x2i = &ndev->aie.mgmt_x2i;

	x2i->mb_head_ptr_reg = mbi->x2i_head_offset;
	x2i->mb_tail_ptr_reg = mbi->x2i_tail_offset;
	x2i->rb_start_addr = mbi->x2i_buffer_addr;
	x2i->rb_size = mbi->x2i_buffer_size;

	i2x->rb_start_addr = mbi->i2x_buffer_addr;
	i2x->rb_size = mbi->i2x_buffer_size;
	i2x->mb_head_ptr_reg = mbi->i2x_head_offset;
	i2x->mb_tail_ptr_reg = mbi->i2x_tail_offset;

	ndev->aie.mgmt_chan_idx = mbi->i2x_msi_idx;
	aie_dump_mgmt_chann_debug(&ndev->aie);

	ndev->mbox = xdnam_mailbox_create(&xdna->ddev, &mbox_res);
	if (!ndev->mbox) {
		XDNA_ERR(xdna, "failed to create mailbox device");
		return -ENODEV;
	}

	ndev->aie.mgmt_chann = xdna_mailbox_alloc_channel(ndev->mbox);
	if (!ndev->aie.mgmt_chann) {
		XDNA_ERR(xdna, "failed to alloc mailbox channel");
		return -ENODEV;
	}

	/* Firmware-initiated messages arrive with mailbox id 0. */
	xdna_mailbox_set_async_cb(ndev->aie.mgmt_chann, ndev,
				  aie4_mgmt_async_event_handler);

	mgmt_mb_irq = pci_irq_vector(pdev, ndev->aie.mgmt_chan_idx);
	if (mgmt_mb_irq < 0) {
		XDNA_ERR(xdna, "failed to alloc irq vector, return %d", mgmt_mb_irq);
		ret = mgmt_mb_irq;
		goto free_channel;
	}

	/*
	 * At any given time, at most AMDXDNA_MAX_ASYNC_EVENT_BUFS async event
	 * messages plus 1 other management command can be unresponded.
	 */
	ret = xdna_mailbox_start_channel(ndev->aie.mgmt_chann,
					 &ndev->aie.mgmt_x2i,
					 &ndev->aie.mgmt_i2x,
					 NO_IOHUB,
					 mgmt_mb_irq,
					 AMDXDNA_MAX_ASYNC_EVENT_BUFS + 1);
	if (ret) {
		XDNA_ERR(xdna, "failed to start management mailbox channel");
		ret = -EINVAL;
		goto free_channel;
	}

	XDNA_DBG(xdna, "Mailbox management channel created");
	return 0;

free_channel:
	xdna_mailbox_free_channel(ndev->aie.mgmt_chann);
	ndev->aie.mgmt_chann = NULL;
	return ret;
}

static int aie4_mailbox_init(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	struct mailbox_info mbox_info;
	int ret;

	ret = aie4_mailbox_info(xdna, &mbox_info);
	if (ret)
		return ret;

	return aie4_mailbox_start(xdna, &mbox_info);
}

static void aie4_fw_unload(struct amdxdna_dev_hdl *ndev)
{
	aie_psp_stop(ndev->aie.psp_hdl);
	aie_smu_fini(ndev->aie.smu_hdl);
}

static int aie4_fw_load(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie_smu_init(ndev->aie.smu_hdl);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "failed to init smu, ret %d", ret);
		return ret;
	}

	ret = aie_psp_start(ndev->aie.psp_hdl);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "failed to start psp, ret %d", ret);
		aie_smu_fini(ndev->aie.smu_hdl);
	}

	return ret;
}

static int aie4_pci_config_fw(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_config_fw(ndev);
#ifdef AMDXDNA_NPU3A
	if (!ret)
		ret = aie4_iommu_bypass_echo(ndev);
#endif
	return ret;
}

/*
 * Suspend the firmware before a failed restart tears its mailbox down, as
 * aie4_teardown_fw() does. Firmware withdraws PMFW's consent to power-off on
 * the first driver message and grants it again only while handling SUSPEND,
 * so without one the aie4_fw_unload() of a failed probe or resume cannot power
 * the NPU off, and the SMU then refuses every later probe. A timed-out message
 * destroys the channel, and then no SUSPEND can be sent.
 */
static void aie4_restart_unwind_suspend(struct amdxdna_dev_hdl *ndev)
{
	if (ndev->aie.mgmt_chann)
		aie4_suspend_fw(ndev);
}

/* Query and configure the firmware once its mailbox is up. */
static int aie4_pf_hw_config(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_query_fw(ndev);
	if (ret)
		return ret;

	return aie4_pci_config_fw(ndev);
}

//FIX this after fw_load can work after FLR
static int aie4_pf_hw_restart(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_mailbox_init(ndev);
	if (ret)
		return ret;

	ret = aie4_pf_hw_config(ndev);
	if (ret)
		goto mbox_fini;

	return 0;

mbox_fini:
	aie4_restart_unwind_suspend(ndev);
	aie4_mailbox_fini(ndev);
	/* Drain notification workers after the mailbox is stopped. */
	amdxdna_async_events_fini(&ndev->aie);
	return ret;
}

static int aie4_pf_hw_start(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_fw_load(ndev);
	if (ret)
		return ret;

	ret = aie4_pf_hw_restart(ndev);
	if (ret)
		goto fw_unload;

	return 0;

fw_unload:
	aie4_fw_unload(ndev);
	return ret;
}

static void aie4_teardown_fw(struct amdxdna_dev_hdl *ndev)
{
	aie4_suspend_fw(ndev);
	aie4_mailbox_fini(ndev);
	aie4_fw_unload(ndev);
}

static void aie4_pf_hw_stop(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	aie4_teardown_fw(ndev);
	/* Drain notification workers after the mailbox is torn down. */
	amdxdna_async_events_fini(&ndev->aie);
}

static int aie4_vf_hw_start(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_mailbox_init(ndev);
	if (ret)
		return ret;

	ret = aie4_query_fw(ndev);
	if (ret)
		goto mbox_fini;

	ret = aie4_setup_aie(ndev);
	if (ret)
		goto mbox_fini;

	return 0;

mbox_fini:
	aie4_mailbox_fini(ndev);
	/* Drain notification workers after the mailbox is stopped. */
	amdxdna_async_events_fini(&ndev->aie);
	return ret;
}

static void aie4_vf_hw_stop(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!AIE4_PART_PER_HWCTX(xdna))
		aie4_partition_destroy(ndev, ndev->partition_id);
	aie4_mailbox_fini(ndev);
	/*
	 * Drain after the mailbox is torn down, so that no notification worker
	 * it queued runs after this returns.
	 */
	amdxdna_async_events_fini(&ndev->aie);
}

/* Query, configure and set up the firmware once its mailbox is up. */
static int aie4_classic_hw_config(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_query_fw(ndev);
	if (ret)
		return ret;

	ret = aie4_pci_config_fw(ndev);
	if (ret)
		return ret;

	return aie4_setup_aie(ndev);
}

//FIX this after fw_load can work after FLR
static int aie4_classic_hw_restart(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_mailbox_init(ndev);
	if (ret)
		return ret;

	ret = aie4_classic_hw_config(ndev);
	if (ret)
		goto mbox_fini;

	return 0;

mbox_fini:
	aie4_restart_unwind_suspend(ndev);
	aie4_mailbox_fini(ndev);
	/* Unarm a partially-armed async pool after the mailbox is stopped. */
	amdxdna_async_events_fini(&ndev->aie);
	return ret;
}

static int aie4_classic_hw_start(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_fw_load(ndev);
	if (ret)
		return ret;

	ret = aie4_classic_hw_restart(ndev);
	if (ret)
		goto fw_unload;

	return 0;

fw_unload:
	aie4_fw_unload(ndev);
	return ret;
}

static void aie4_classic_hw_stop(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	if (!AIE4_PART_PER_HWCTX(xdna))
		aie4_partition_destroy(ndev, ndev->partition_id);
	aie4_teardown_fw(ndev);
	/*
	 * Unarm and drain after the mailbox is torn down, because the teardown
	 * runs the async callback of every armed slot and each one queues a
	 * report worker. The buffers stay allocated for the next hw start.
	 */
	amdxdna_async_events_fini(&ndev->aie);
}

static int aie4_request_firmware(struct amdxdna_dev_hdl *ndev,
				 const char *npufw_name, const char *certfw_name,
				 const struct firmware **npufw,
				 const struct firmware **certfw)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	char fw_name[128];
	int ret;

	ret = snprintf(fw_name, sizeof(fw_name), "amdnpu/%04x_%02x/%s",
		       pdev->device, pdev->revision, npufw_name);
	if (ret >= sizeof(fw_name)) {
		XDNA_ERR(xdna, "npu firmware path is truncated");
		return -EINVAL;
	}

	ret = request_firmware(npufw, fw_name, &pdev->dev);
	if (ret) {
		XDNA_DBG(xdna, "no firmware %s, ret %d", fw_name, ret);
		return ret;
	}

	ret = snprintf(fw_name, sizeof(fw_name), "amdnpu/%04x_%02x/%s",
		       pdev->device, pdev->revision, certfw_name);
	if (ret >= sizeof(fw_name)) {
		XDNA_ERR(xdna, "cert firmware path is truncated");
		ret = -EINVAL;
		goto release_npufw;
	}

	ret = request_firmware(certfw, fw_name, &pdev->dev);
	if (ret) {
		XDNA_INFO(xdna, "no firmware file %s found", fw_name);
		goto release_npufw;
	}

	if ((*certfw)->size > CERTFW_MAX_SIZE) {
		XDNA_ERR(xdna, "CERTFW over maximum size of 32 KB + 256 B");
		ret = -EINVAL;
		goto release_certfw;
	}

	return 0;

release_certfw:
	release_firmware(*certfw);
release_npufw:
	release_firmware(*npufw);

	return ret;
}

static void aie4_release_firmware(struct amdxdna_dev_hdl *ndev,
				  const struct firmware *npufw,
				  const struct firmware *certfw)
{
	release_firmware(certfw);
	release_firmware(npufw);
}

static struct psp_device *aie4_create_psp(struct amdxdna_dev_hdl *ndev,
					  const char *npufw_name,
					  const char *certfw_name,
					  void __iomem *tbl[PCI_NUM_RESOURCES])
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	const struct firmware *npufw, *certfw;
	struct psp_config psp_conf;
	struct psp_device *psp;
	int ret, i;

	ret = aie4_request_firmware(ndev, npufw_name, certfw_name, &npufw, &certfw);
	if (ret)
		return ERR_PTR(ret);

	psp_conf.fw_size = npufw->size;
	psp_conf.fw_buf = npufw->data;
	psp_conf.certfw_size = certfw->size;
	psp_conf.certfw_buf = certfw->data;
	psp_conf.arg2_mask = ~0;
	psp_conf.notify_val = PSP_NOTIFY_INTR;
	for (i = 0; i < PSP_MAX_REGS; i++)
		psp_conf.psp_regs[i] = tbl[PSP_REG_BAR(ndev, i)] + PSP_REG_OFF(ndev, i);
	psp = aiem_psp_create(&xdna->ddev, &psp_conf);
	aie4_release_firmware(ndev, npufw, certfw);
	if (!psp) {
		XDNA_ERR(xdna, "failed to create psp");
		return ERR_PTR(-ENOMEM);
	}

	return psp;
}

/* Firmware images, tried in this order: DEV, RSA, LMS signed */
static const struct {
	const char	*npufw;
	const char	*certfw;
} aie4_fw_images[] = {
	{ "npu.dev.sbin", "cert.dev.sbin" },
	{ "npu.rsa.sbin", "cert.rsa.sbin" },
	{ "npu.lms.sbin", "cert.lms.sbin" },
};

/*
 * Create the SMU, find the first image the PSP starts and keep its PSP
 * in ndev->aie.psp_hdl for aie4_fw_load(). The SMU is not powered off
 * between tries. The started firmware is left running, so probe skips
 * aie4_fw_load().
 */
static int aie4_select_fw(struct amdxdna_dev_hdl *ndev,
			  void __iomem *tbl[PCI_NUM_RESOURCES])
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	struct smu_config smu_conf = {};
	struct psp_device *psp;
	int ret, i;

	for (i = 0; i < SMU_MAX_REGS; i++)
		smu_conf.smu_regs[i] = tbl[SMU_REG_BAR(ndev, i)] + SMU_REG_OFF(ndev, i);
	ndev->aie.smu_hdl = aiem_smu_create(&xdna->ddev, &smu_conf);
	if (!ndev->aie.smu_hdl) {
		XDNA_ERR(xdna, "failed to create smu");
		return -ENOMEM;
	}

	/*
	 * Probe only: power the SMU on once, then try each firmware image as a
	 * fallback. While the SMU is on, the PSP rejects an image that does not
	 * match this platform, and the next one is tried. On success, the
	 * firmware is up and running when this function returns.
	 */
	ret = aie_smu_init(ndev->aie.smu_hdl);
	if (ret) {
		XDNA_ERR(xdna, "failed to init smu, ret %d", ret);
		return ret;
	}

	ret = -ENOENT;
	for (i = 0; i < ARRAY_SIZE(aie4_fw_images); i++) {
		psp = aie4_create_psp(ndev, aie4_fw_images[i].npufw,
				      aie4_fw_images[i].certfw, tbl);
		if (IS_ERR(psp)) {
			/* A missing image must not hide why an earlier one failed */
			if (PTR_ERR(psp) != -ENOENT)
				ret = PTR_ERR(psp);
			if (PTR_ERR(psp) == -ENOMEM)
				break;
			continue;
		}

		ret = aie_psp_start(psp);
		if (!ret) {
			XDNA_INFO(xdna, "firmware %s started", aie4_fw_images[i].npufw);
			ndev->aie.psp_hdl = psp;
			return 0;
		}
		/* A timed out command may still be reading the buffers */
		if (ret != -EIO)
			break;
		aiem_psp_destroy(psp);
		XDNA_INFO(xdna, "%s is not for this platform, trying the next firmware",
			  aie4_fw_images[i].npufw);
	}

	XDNA_ERR(xdna, "no working NPU firmware found, ret %d", ret);
	aie_smu_fini(ndev->aie.smu_hdl);
	return ret;
}

static int aie4m_pcidev_init(struct amdxdna_dev *xdna)
{
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	struct amdxdna_dev_hdl *ndev;
	void __iomem *tbl[PCI_NUM_RESOURCES] = {0};
	unsigned long bars = 0;
	int ret, i;

	ndev = aie4_dev_hdl_alloc(xdna);
	if (!ndev)
		return -ENOMEM;

	ndev->priv = xdna->dev_info->dev_priv;
	ndev->ctx_switch_hysteresis_us = AIE4_CTX_HYSTERESIS_US;
	ndev->pw_mode = POWER_MODE_DEFAULT;

	/* Enable managed PCI device */
	ret = pcim_enable_device(pdev);
	if (ret) {
		XDNA_ERR(xdna, "pcim enable device failed, ret %d", ret);
		return ret;
	}

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		XDNA_ERR(xdna, "failed to set DMA mask to 64:%d", ret);
		return ret;
	}

	for (i = 0; i < PSP_MAX_REGS; i++)
		set_bit(PSP_REG_BAR(ndev, i), &bars);
	for (i = 0; i < SMU_MAX_REGS; i++)
		set_bit(SMU_REG_BAR(ndev, i), &bars);
	set_bit(xdna->dev_info->mbox_bar, &bars);
	set_bit(xdna->dev_info->sram_bar, &bars);
	set_bit(xdna->dev_info->doorbell_bar, &bars);

	for (i = 0; i < PCI_NUM_RESOURCES; i++) {
		if (!test_bit(i, &bars))
			continue;
		tbl[i] = pcim_iomap(pdev, i, 0);
		if (!tbl[i]) {
			XDNA_ERR(xdna, "map bar %d failed", i);
			return -ENOMEM;
		}
	}

	ndev->mbox_base = tbl[xdna->dev_info->mbox_bar];
	ndev->rbuf_base = tbl[xdna->dev_info->sram_bar];
	ndev->doorbell_base = tbl[xdna->dev_info->doorbell_bar];

	pci_set_master(pdev);

	ret = aie4_irq_init(xdna);
	if (ret)
		return ret;

	/* Leaves the firmware running; probe skips aie4_fw_load() */
	if (ndev->priv->npufw_path && ndev->priv->certfw_path) {
		ret = aie4_select_fw(ndev, tbl);
		if (ret)
			return ret;
	}

	amdxdna_vbnv_init(xdna);

	XDNA_DBG(xdna, "init finished");
	return 0;
}

/*
 * Validate a doorbell mmap request and return the pfn to map.  The page offset
 * must belong to one of the caller's own user-mode contexts (kernel-mode
 * contexts carry the AMDXDNA_INVALID_DOORBELL_OFFSET sentinel and are never
 * mappable), and the resulting page must lie fully within the doorbell BAR - a
 * BAR whose length is not page-aligned must not leak the MMIO that follows it
 * into the last mapped page.
 */
static int aie4_doorbell_mmap_pfn(struct amdxdna_client *client,
				  unsigned long vm_pgoff, unsigned long *pfnp)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	const struct amdxdna_dev_priv *npriv = xdna->dev_info->dev_priv;
	phys_addr_t res_start, res_end;
	struct amdxdna_hwctx *hwctx;
	unsigned long hwctx_id, pfn;
	bool owned = false;
	int idx;

	mutex_lock(&xdna->dev_lock);
	idx = srcu_read_lock(&client->hwctx_srcu);
	amdxdna_for_each_hwctx(client, hwctx_id, hwctx) {
		if (hwctx->doorbell_offset == AMDXDNA_INVALID_DOORBELL_OFFSET)
			continue;
		if (vm_pgoff == (hwctx->doorbell_offset >> PAGE_SHIFT)) {
			owned = true;
			break;
		}
	}
	srcu_read_unlock(&client->hwctx_srcu, idx);
	mutex_unlock(&xdna->dev_lock);
	if (!owned)
		return -EINVAL;

	res_start = pci_resource_start(pdev, xdna->dev_info->doorbell_bar) + npriv->doorbell_off;
	res_end = pci_resource_end(pdev, xdna->dev_info->doorbell_bar);
	pfn = PHYS_PFN(res_start) + vm_pgoff;
	if (((phys_addr_t)pfn << PAGE_SHIFT) + PAGE_SIZE - 1 > res_end)
		return -EINVAL;

	*pfnp = pfn;
	return 0;
}

static int aie4_doorbell_mmap(struct amdxdna_client *client, struct vm_area_struct *vma)
{
	struct amdxdna_dev *xdna = client->xdna;
	unsigned long pfn;
	int ret;

	if (vma_pages(vma) != 1) {
		XDNA_ERR(xdna, "can only map one page, got %ld", vma_pages(vma));
		return -EINVAL;
	}

	ret = aie4_doorbell_mmap_pfn(client, vma->vm_pgoff, &pfn);
	if (ret) {
		XDNA_ERR(xdna, "Invalid doorbell page offset 0x%lx", vma->vm_pgoff);
		return ret;
	}

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);
	ret = io_remap_pfn_range(vma, vma->vm_start, pfn, PAGE_SIZE, vma->vm_page_prot);

	XDNA_DBG(xdna, "doorbell ret %d", ret);
	return ret;
}

/*
 * AIE4 Suspend/Resume steps per device type.
 * -> SUSPEND
 * <- RESUME
 *
 * Y(R1) = Runtime PM only; blocks PF suspend if a VF is alive
 * Y(R2) = Runtime PM only; VF does not send mailbox message, PF tears down stateless FW
 *
 *                              | PF    | VF    | Classic
 * -----------------------------|-------|-------|--------
 * -> vfs_alive                 | Y(R1) |  -    |   -
 * -> hwctx_suspend_all         |  -    |  Y    |   Y
 * -> partition_fini            |  -    | Y(R2) |   Y
 * -> teardown_fw               |  Y    |  -    |   Y
 *      -> suspend_fw           |  Y    |  -    |   Y
 * -> mailbox_fini              |  -    |  Y    |   -
 * -> async_events_fini         |  Y    |  Y    |   Y
 *    ---- power boundary ----
 * <- pci_enable + set_master   |  Y    |  Y    |   Y
 * <- fw_load                   |  Y    |  -    |   Y
 * <- mailbox_init              |  Y    |  Y    |   Y
 * <- query_fw                  |  Y    |  Y    |   Y
 *      <- restore_force_preempt|  Y    |  Y    |   Y
 * <- config_fw                 |  Y    |  -    |   Y
 *      <- calibrate_clock      |  Y    |  -    |   Y
 *      <- attach_work_buffer   |  Y    |  -    |   Y
 *      <- set_dpm_compute      |  Y    |  -    |   Y
 *      <- set_dpm_bw_busyness  |  Y    |  -    |   Y
 *      <- set_pwr_ovr_table    |  Y    |  -    |   Y
 *      <- set_dpm_cap_table    |  Y    |  -    |   Y
 * <- setup_aie                 |  -    |  Y    |   Y
 *      <- partition_init       |  -    |  Y    |   Y
 *      <- async_events_init    |  -    |  Y    |   Y
 *      <- set_power_hint       |  -    |  Y    |   Y
 *      <- restore_power_mode   |  -    |  Y    |   Y
 * <- hwctx_resume_all          |  -    |  Y    |   Y
 * <- restore VFs               |  Y    |  -    |   -
 */

static int aie4_pf_suspend(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	/* PF suspend will cleanup fw status */
	aie4_pf_hw_stop(ndev);

	XDNA_DBG(xdna, "pf suspend done");
	return 0;
}

static int aie4_pf_runtime_suspend(struct amdxdna_dev *xdna)
{
	int ret;

	ret = aie4_vfs_alive(xdna);
	if (ret)
		return ret;

	return aie4_pf_suspend(xdna);
}

static int aie4_vf_suspend(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	aie4_hwctx_suspend_all(ndev, false);
	/* when PF and VF both present, PF suspend will do cleanup for all VFs */
	aie4_mailbox_fini(ndev);
	/* Drain the pool after the mailbox is torn down, as hw stop does. */
	amdxdna_async_events_fini(&ndev->aie);

	XDNA_DBG(xdna, "vf suspend done");
	return 0;
}

static int aie4_vf_runtime_suspend(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	aie4_hwctx_suspend_all(ndev, false);
	aie4_vf_hw_stop(ndev);

	XDNA_DBG(xdna, "vf runtime suspend done");
	return 0;
}

static int aie4_classic_suspend(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	aie4_hwctx_suspend_all(ndev, false);
	aie4_classic_hw_stop(ndev);

	XDNA_DBG(xdna, "classic suspend done");
	return 0;
}

static int aie4_restore_sriov(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	/* restore fw status */
	if (ndev->num_vfs) {
		if (pci_num_vf(pdev) != ndev->num_vfs) {
			XDNA_ERR(xdna, "inconsistent vf number");
			return -EINVAL;
		}
		ret = aie4_create_vfs(ndev, ndev->num_vfs);
		if (ret) {
			XDNA_ERR(xdna, "create vfs failed, %d", ret);
			return ret;
		}
		XDNA_DBG(xdna, "restored num_vfs %d", ndev->num_vfs);
	}

	return 0;
}

static int aie4_pf_resume(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	ret = pci_enable_device(pdev);
	if (ret) {
		XDNA_ERR(xdna, "enable pci device failed %d", ret);
		return ret;
	}
	pci_set_master(pdev);

	ret = aie4_pf_hw_start(ndev);
	if (ret) {
		XDNA_ERR(xdna, "hw_start failed %d", ret);
		goto pci_disable;
	}

	ret = aie4_restore_sriov(ndev);
	if (ret)
		goto hw_stop;

	XDNA_DBG(xdna, "pf resume done");
	return 0;
hw_stop:
	aie4_pf_hw_stop(ndev);
pci_disable:
	pci_disable_device(pdev);
	return ret;
}

static int aie4_vf_resume(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	ret = pci_enable_device(pdev);
	if (ret) {
		XDNA_ERR(xdna, "enable pci device failed %d", ret);
		return ret;
	}
	pci_set_master(pdev);

	ret = aie4_vf_hw_start(ndev);
	if (ret) {
		XDNA_ERR(xdna, "hw_start failed %d", ret);
		goto pci_disable;
	}

	aie4_restore_ctx_restore_pool(ndev);

	ret = aie4_hwctx_resume_all(ndev);
	if (ret) {
		XDNA_ERR(xdna, "hwctx_resume failed %d", ret);
		goto hw_clear;
	}

	XDNA_DBG(xdna, "vf resume done");
	return 0;

hw_clear:
	aie4_hwctx_suspend_all(ndev, true);
	aie4_vf_hw_stop(ndev);
pci_disable:
	pci_disable_device(pdev);
	return ret;
}

static int aie4_classic_resume(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	ret = pci_enable_device(pdev);
	if (ret) {
		XDNA_ERR(xdna, "enable pci device failed %d", ret);
		return ret;
	}
	pci_set_master(pdev);

	ret = aie4_classic_hw_start(ndev);
	if (ret) {
		XDNA_ERR(xdna, "hw_start failed %d", ret);
		goto pci_disable;
	}

	aie4_restore_ctx_restore_pool(ndev);

	ret = aie4_hwctx_resume_all(ndev);
	if (ret) {
		XDNA_ERR(xdna, "hwctx_resume failed %d", ret);
		goto hw_clear;
	}

	XDNA_DBG(xdna, "classic resume done");
	return 0;
hw_clear:
	aie4_hwctx_suspend_all(ndev, true);
	aie4_classic_hw_stop(ndev);
pci_disable:
	pci_disable_device(pdev);
	return ret;
}

/*
 * AIE4 FLR (Function Level Reset) steps per device type.
 * -> reset_prepare: called before the kernel issues the PCI FLR
 * <- reset_done:    called after the kernel completes the PCI FLR
 *
 *                              | PF  | VF  | Classic
 * -----------------------------|-----|-----|--------
 * -> dpt_reset_prepare         |  Y  |  Y  |   Y
 * -> hwctx_disconnect_all      |  -  |  Y  |   Y
 * -> mailbox_fini              |  Y  |  Y  |   Y
 * -> async_events_fini         |  Y  |  Y  |   Y
 * -> fw_clear_alive            |  Y  |  Y  |   Y
 *    ---- FLR boundary ----
 * <- zero_work_buffer          |  Y  |  -  |   Y
 * <- fw_load(*)                |  Y  |  -  |   Y
 * <- mailbox_init              |  Y  |  Y  |   Y
 * <- query_fw                  |  Y  |  Y  |   Y
 *      <- restore_force_preempt|  Y  |  Y  |   Y
 * <- config_fw                 |  Y  |  -  |   Y
 *      <- calibrate_clock      |  Y  |  -  |   Y
 *      <- attach_work_buffer   |  Y  |  -  |   Y
 *      <- set_dpm_compute      |  Y  |  -  |   Y
 *      <- set_dpm_bw_busyness  |  Y  |  -  |   Y
 *      <- set_pwr_ovr_table    |  Y  |  -  |   Y
 *      <- set_dpm_cap_table    |  Y  |  -  |   Y
 * <- setup_aie                 |  -  |  Y  |   Y
 *      <- partition_init       |  -  |  Y  |   Y
 *      <- async_events_init    |  -  |  Y  |   Y
 *      <- set_power_hint       |  -  |  Y  |   Y
 *      <- restore_power_mode   |  -  |  Y  |   Y
 * <- restore_sriov             |  Y  |  -  |   -
 * <- hwctx_reconnect_all       |  -  |  Y  |   Y
 * <- dpt_reset_done            |  Y  |  Y  |   Y
 *
 * dpt_reset_prepare runs first: it sends no firmware messages, so it is
 * safe even when the firmware is unresponsive, and it releases any parked
 * watcher and stops the DPT poll timer before the rest of the teardown
 * runs. Anything the firmware logs after that snapshot is lost, but no
 * step below it sends a command, so there is nothing left to report. It
 * mirrors dpt_reset_done, which cannot move earlier because
 * amdxdna_dpt_resume_chan() re-attaches the ring over the mailbox.
 *
 * dpt_reset_done runs last and only when everything before it succeeded,
 * so a failed reset leaves the DPT channels suspended rather than active
 * on firmware that is not running.
 *
 * (*) fw_load is required but currently skipped for PF and Classic due to a
 *     firmware bug where reloading FW after FLR causes a hang; see
 *     aie4_pf_hw_restart and aie4_classic_hw_restart.
 *     Will be replaced with the full hw_start once the bug is fixed.
 */
static void aie4_pf_reset_prepare(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	/* Release parked DPT watchers and stop the poll timer; see above. */
	amdxdna_dpt_reset_prepare(xdna);

	/*
	 * PF has no hwctx. Just tear down the mailbox so no firmware
	 * messages are sent during the reset window, then clear the
	 * alive flag so reset_done can poll for FW readiness.
	 */
	aie4_mailbox_fini(ndev);
	/* Drain notification workers before the reset window. */
	amdxdna_async_events_fini(&ndev->aie);

	aie4_fw_clear_alive(xdna);
}

static void aie4_pf_reset_done(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	/*
	 * FLR only: suspend asks firmware to release the work buffer, so what it
	 * leaves behind is retained state. An FLR gives it no such chance - PMFW
	 * resets the NPU underneath it, possibly mid-DMA - so the contents are
	 * indeterminate and are cleared before firmware attaches them again.
	 */
	aie4_zero_work_buffer(ndev);

	/* PF owns firmware: must do full fw_load cycle after FLR. */
	ret = aie4_pf_hw_restart(ndev);
	if (ret)
		goto done;

	ret = aie4_restore_sriov(ndev);
	if (ret)
		goto hw_stop;

	/*
	 * Restart DPT last and only here: on any failure above the channels
	 * stay SUSPENDED, which turns a would-be watcher away with
	 * -ESHUTDOWN rather than parking it on firmware that is not running.
	 */
	ret = amdxdna_dpt_reset_done(xdna);
	if (ret)
		XDNA_WARN(xdna, "DPT restart after reset failed: %d", ret);

	XDNA_INFO(xdna, "reset done, service online");
	return;

hw_stop:
	aie4_pf_hw_stop(ndev);
done:
	XDNA_ERR(xdna, "reset failed: %d, service offline", ret);
}

static void aie4_vf_reset_prepare(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	/* Release parked DPT watchers and stop the poll timer; see above. */
	amdxdna_dpt_reset_prepare(xdna);

	aie4_hwctx_disconnect_all(ndev);
	aie4_mailbox_fini(ndev);
	/*
	 * Drain after the mailbox is torn down, so that no notification worker
	 * it queued runs into the reset window.
	 */
	amdxdna_async_events_fini(&ndev->aie);
	aie4_fw_clear_alive(xdna);
}

static void aie4_vf_reset_done(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	/* VF does not own firmware: skip fw_load, PF has already reloaded it. */
	ret = aie4_vf_hw_start(ndev);
	if (ret)
		goto done;

	ret = aie4_hwctx_reconnect_all(ndev);
	if (ret)
		goto hw_clear;

	/*
	 * Restart DPT last and only here: on any failure above the channels
	 * stay SUSPENDED, which turns a would-be watcher away with
	 * -ESHUTDOWN rather than parking it on firmware that is not running.
	 */
	ret = amdxdna_dpt_reset_done(xdna);
	if (ret)
		XDNA_WARN(xdna, "DPT restart after reset failed: %d", ret);

	XDNA_INFO(xdna, "reset done, service online");
	return;

hw_clear:
	aie4_hwctx_suspend_all(ndev, true);
	aie4_vf_hw_stop(ndev);
done:
	XDNA_ERR(xdna, "reset failed: %d, service offline", ret);
}

static void aie4_classic_reset_prepare(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	/* Release parked DPT watchers and stop the poll timer; see above. */
	amdxdna_dpt_reset_prepare(xdna);

	/*
	 * In this situation, the firmware might be not responsive, thus
	 * do NOT send and mailbox messages, just cleanup driver cached
	 * info and mark in-flight traffic for future to abort operation
	 * when reset done and system is back.
	 */
	aie4_hwctx_disconnect_all(ndev);

	aie4_mailbox_fini(ndev);

	/*
	 * Unarm and drain after the mailbox is torn down, because the teardown
	 * runs the async callback of every armed slot and each one queues a
	 * report worker. The buffers outlive the reset; the FLR clears the
	 * firmware registrations, and reset_done arms the slots again.
	 */
	amdxdna_async_events_fini(&ndev->aie);

	aie4_fw_clear_alive(xdna);
}

static void aie4_classic_reset_done(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	/* FLR only, for the reason in aie4_pf_reset_done(). */
	aie4_zero_work_buffer(ndev);

	ret = aie4_classic_hw_restart(ndev);
	if (ret)
		goto done;

	ret = aie4_hwctx_reconnect_all(ndev);
	if (ret)
		goto hw_clear;

	/*
	 * Restart DPT last and only here: on any failure above the channels
	 * stay SUSPENDED, which turns a would-be watcher away with
	 * -ESHUTDOWN rather than parking it on firmware that is not running.
	 */
	ret = amdxdna_dpt_reset_done(xdna);
	if (ret)
		XDNA_WARN(xdna, "DPT restart after reset failed: %d", ret);

	XDNA_INFO(xdna, "reset done, service online");
	return;

hw_clear:
	aie4_hwctx_suspend_all(ndev, true);
	aie4_classic_hw_stop(ndev);
done:
	XDNA_ERR(xdna, "reset failed: %d, service offline", ret);
}

static int aie4_pf_init(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev;
	int ret;

	ret = aie4m_pcidev_init(xdna);
	if (ret)
		return ret;

	/*
	 * aie4_select_fw() left the firmware running, so probe skips
	 * aie4_fw_load(). No driver message has reached the firmware yet, and
	 * until one does it lets aie4_fw_unload() shut it down through PSP and
	 * SMU without a SUSPEND, which a failed mailbox setup relies on.
	 */
	ndev = xdna->dev_handle;
	ret = aie4_mailbox_init(ndev);
	if (ret)
		goto fw_unload;

	/* Not fatal: without a work buffer firmware refuses hardware contexts */
	ret = aie4_alloc_work_buffer(ndev);
	if (ret)
		XDNA_WARN(xdna, "No work buffer, ret %d, hardware context creation will fail",
			  ret);

	/*
	 * The PF registers no report buffers. Under SR-IOV firmware would write
	 * the AIE tile-error backtraces of every context into them, but the PF
	 * cannot query the AIE metadata needed to decode those. Its pool still
	 * carries its firmware notifications.
	 */
	ret = amdxdna_async_events_alloc(&ndev->aie, 0);
	if (ret) {
		XDNA_ERR(xdna, "Allocate async events failed, ret %d", ret);
		goto mbox_fini;
	}

	ret = aie4_pf_hw_config(ndev);
	if (ret)
		goto mbox_fini;

	aie4_xdna_init(xdna);
	return 0;

mbox_fini:
	aie4_restart_unwind_suspend(ndev);
	aie4_mailbox_fini(ndev);
	/* Drain notification workers after the mailbox is stopped. */
	amdxdna_async_events_fini(&ndev->aie);
fw_unload:
	aie4_fw_unload(ndev);
	amdxdna_async_events_free(&ndev->aie);
	aie4_free_work_buffer(ndev);
	return ret;
}

static int aie4_vf_init(struct amdxdna_dev *xdna)
{
	int ret;

	ret = aie4m_pcidev_init(xdna);
	if (ret)
		return ret;

	/*
	 * A VF registers no report buffers, by design. Under SR-IOV firmware
	 * never writes AIE tile-error backtraces into a VF's buffers, so a VF's
	 * buffers would only ever carry the health report of a context error.
	 * The context error itself still reaches the VF as a firmware
	 * notification, which needs the pool's workqueue.
	 */
	ret = amdxdna_async_events_alloc(&xdna->dev_handle->aie, 0);
	if (ret) {
		XDNA_ERR(xdna, "Allocate async events failed, ret %d", ret);
		return ret;
	}

	ret = aie4_vf_hw_start(xdna->dev_handle);
	if (ret)
		goto free_async_events;

	aie4_xdna_init(xdna);
	return 0;

free_async_events:
	amdxdna_async_events_free(&xdna->dev_handle->aie);
	return ret;
}

static int aie4_classic_init(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev;
	int ret;

	ret = aie4m_pcidev_init(xdna);
	if (ret)
		return ret;

	/* Running firmware, no message sent yet: see aie4_pf_init() */
	ndev = xdna->dev_handle;
	ret = aie4_mailbox_init(ndev);
	if (ret)
		goto fw_unload;

	/* Not fatal: without a work buffer firmware refuses hardware contexts */
	ret = aie4_alloc_work_buffer(ndev);
	if (ret)
		XDNA_WARN(xdna, "No work buffer, ret %d, hardware context creation will fail",
			  ret);

	/*
	 * Fatal: the firmware notifications need the pool. Report buffers
	 * that cannot be allocated leave it with fewer slots instead.
	 */
	ret = amdxdna_async_events_alloc(&ndev->aie, AMDXDNA_MAX_ASYNC_EVENT_BUFS);
	if (ret) {
		XDNA_ERR(xdna, "Allocate async events failed, ret %d", ret);
		goto mbox_fini;
	}

	ret = aie4_classic_hw_config(ndev);
	if (ret)
		goto mbox_fini;

	aie4_xdna_init(xdna);
	return 0;

mbox_fini:
	aie4_restart_unwind_suspend(ndev);
	aie4_mailbox_fini(ndev);
	/* Unarm a partially-armed async pool after the mailbox is stopped. */
	amdxdna_async_events_fini(&ndev->aie);
fw_unload:
	aie4_fw_unload(ndev);
	/* Firmware is stopped; no slot buffer can be written. */
	amdxdna_async_events_free(&ndev->aie);
	aie4_free_work_buffer(ndev);
	return ret;
}

static void aie4_pf_fini(struct amdxdna_dev *xdna)
{
	int ret;

	aie4_xdna_fini(xdna);

	ret = aie4_sriov_stop(xdna->dev_handle);
	if (ret == -EPERM)
		XDNA_ERR(xdna, "VFs in passthrough - VM disruption expected");
	else if (ret)
		XDNA_ERR(xdna, "Unconfig sriov failed: %d", ret);

	aie4_pf_hw_stop(xdna->dev_handle);
	amdxdna_async_events_free(&xdna->dev_handle->aie);
	aie4_free_work_buffer(xdna->dev_handle);
	aie4_dev_hdl_fini(xdna->dev_handle);
}

static void aie4_vf_fini(struct amdxdna_dev *xdna)
{
	aie4_xdna_fini(xdna);
	aie4_vf_hw_stop(xdna->dev_handle);
	aie4_free_ctx_restore_pool(xdna->dev_handle);
	amdxdna_async_events_free(&xdna->dev_handle->aie);
	aie4_dev_hdl_fini(xdna->dev_handle);
}

static void aie4_classic_fini(struct amdxdna_dev *xdna)
{
	aie4_xdna_fini(xdna);
	aie4_classic_hw_stop(xdna->dev_handle);
	aie4_free_ctx_restore_pool(xdna->dev_handle);
	amdxdna_async_events_free(&xdna->dev_handle->aie);
	aie4_free_work_buffer(xdna->dev_handle);
	aie4_dev_hdl_fini(xdna->dev_handle);
}

int aie4_set_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	return ndev->priv->hw_ops->set_dpm(&ndev->aie, dpm_level);
}

void aie4_update_counters(struct amdxdna_dev_hdl *ndev)
{
	aie_update_counters(ndev);
}

const struct dpm_clk_freq *aie4_default_dpm_clk_tbl(struct amdxdna_dev_hdl *ndev)
{
	return ndev->priv->dpm_clk_tbl;
}

void aie4_transport_debugfs_init(struct amdxdna_dev *xdna)
{
	/*
	 * Submission mode only applies where the driver runs hw contexts (the
	 * VF and classic paths); the SR-IOV PF has no submission path, so do
	 * not expose the knob there.
	 */
	if (xdna->dev_info->ops != &aie4_pf_ops)
		aie4_debugfs_add_kernel_submit(xdna, true);

	/*
	 * Context switch hysteresis is a system-control runtime config that is
	 * only programmed on the PF/classic hw start paths, never on a VF.
	 * Only expose the knob where the driver actually applies it.
	 */
	if (!to_pci_dev(xdna->ddev.dev)->is_virtfn)
		aie4_debugfs_add_ctx_hysteresis(xdna);

	/*
	 * The driver programs and permits the DPM runtime configs only on the
	 * PF and classic paths (see aie4_runtime_cfg_allow), so expose them
	 * there alone.
	 */
	if (xdna->dev_info->ops != &aie4_vf_ops)
		aie4_debugfs_add_dpm_config(xdna);
}

const struct amdxdna_dev_ops aie4_pf_ops = {
	.init			= aie4_pf_init,
	.fini			= aie4_pf_fini,
	.debugfs_init		= aie4_debugfs_init,
	.sriov_configure        = aie4_sriov_configure,
	.get_aie_info		= aie4_get_info,
	.set_aie_state		= aie4_set_state,
	.get_array		= aie4_get_array,
	.resume			= aie4_pf_resume,
	.suspend		= aie4_pf_suspend,
	.runtime_resume		= aie4_pf_resume,
	.runtime_suspend	= aie4_pf_runtime_suspend, /* additional check on VM passthrough */
	.reset_prepare		= aie4_pf_reset_prepare,
	.reset_done		= aie4_pf_reset_done,
	.register_async_event	= aie4_async_event_register,
	.handle_dev_async_event	= aie4_handle_dev_event,
};

const struct amdxdna_dev_ops aie4_vf_ops = {
	.init			= aie4_vf_init,
	.fini			= aie4_vf_fini,
	.debugfs_init		= aie4_debugfs_init,
	.hwctx_init		= aie4_hwctx_init,
	.hwctx_fini		= aie4_hwctx_fini,
	.hwctx_abort		= aie4_hwctx_abort,
	.hwctx_config		= aie4_hwctx_config,
	.mmap			= aie4_doorbell_mmap,
	.cmd_submit		= aie4_cmd_submit,
	.cmd_wait		= aie4_cmd_wait,
	.get_aie_info		= aie4_get_info,
	.set_aie_state		= aie4_set_state,
	.get_array		= aie4_get_array,
	.resume			= aie4_vf_resume,
	.suspend		= aie4_vf_suspend,
	.runtime_resume		= aie4_vf_resume,
	.runtime_suspend	= aie4_vf_runtime_suspend, /* each VF needs to clean up itself */
	.reset_prepare		= aie4_vf_reset_prepare,
	.reset_done		= aie4_vf_reset_done,
	.register_async_event	= aie4_async_event_register,
	.handle_dev_async_event	= aie4_handle_dev_event,
};

bool aie4_is_vf(struct amdxdna_dev_hdl *ndev)
{
	return ndev->aie.xdna->dev_info->ops == &aie4_vf_ops;
}

const struct amdxdna_dev_ops aie4_classic_ops = {
	.init			= aie4_classic_init,
	.fini			= aie4_classic_fini,
	.debugfs_init		= aie4_debugfs_init,
	.hwctx_init		= aie4_hwctx_init,
	.hwctx_fini		= aie4_hwctx_fini,
	.hwctx_abort		= aie4_hwctx_abort,
	.hwctx_config		= aie4_hwctx_config,
	.mmap			= aie4_doorbell_mmap,
	.cmd_submit		= aie4_cmd_submit,
	.cmd_wait		= aie4_cmd_wait,
	.get_aie_info		= aie4_get_info,
	.set_aie_state		= aie4_set_state,
	.get_array		= aie4_get_array,
	.resume			= aie4_classic_resume,
	.suspend		= aie4_classic_suspend,
	.runtime_resume		= aie4_classic_resume,
	.runtime_suspend	= aie4_classic_suspend,
	.reset_prepare		= aie4_classic_reset_prepare,
	.reset_done		= aie4_classic_reset_done,
	.register_async_event	= aie4_async_event_register,
	.handle_dev_async_event	= aie4_handle_dev_event,
};
