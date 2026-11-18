// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 device ops for the shared aie4 core.
 *
 * Probe runs the shared aie4 version and geometry queries. Those opcodes are
 * carried out through the Xilinx AIE driver by amdxdna_mailbox_ve2.c. The
 * npu12 DRAM work-buffer attach is not used: VE2 CERT has no such buffer, and
 * that opcode stays unimplemented.
 *
 * The ops below are the attachment to the shared aie4 core, which runs the
 * context and kernel-mode command path. The partition and hardware-context
 * opcodes it sends are carried out by amdxdna_mailbox_ve2.c. The transport
 * hooks here ring CERT through an AIE user event, and wake the aie4 cert_comp
 * from the AIE partition's completion callback.
 */

#include <drm/drm_drv.h>
#include <drm/drm_gem.h>
#include <drm/drm_managed.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/xarray.h>

#include "aie4.h"
#include "aie4_host_queue.h"
#include "ve2.h"
#include "amdxdna_ctx.h"
#include "amdxdna_dpt.h"
#include "amdxdna_drv.h"
#include "amdxdna_gem.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_pm.h"

/*
 * Test-only maximum AIE column window. partition_arbitration loads the module
 * with max_col=24 to exercise temporal sharing on a 24-column partition.
 */
static int ve2_max_col;
module_param_named(max_col, ve2_max_col, int, 0644);
MODULE_PARM_DESC(max_col, "Maximum AIE columns available to the VE2 allocator");

/*
 * Layout aie4_hwctx_umq_init() requires when hsa_level2_indirect is set.
 * The KMQ shim passes no queue, so the driver allocates this buffer.
 */
static size_t ve2_hsa_queue_size(void)
{
	return sizeof(struct host_queue_header) +
	       CTX_MAX_CMDS * sizeof(struct host_queue_packet) +
	       CTX_MAX_CMDS * sizeof(struct host_queue_indirect_hdr) +
	       CTX_MAX_CMDS * HSA_MAX_LEVEL2_INDIRECT_ENTRIES *
	       sizeof(struct host_indirect_packet_data);
}

static int ve2_hsa_queue_alloc(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_drm_create_bo args = {
		.type = AMDXDNA_BO_SHARE,
		.size = ve2_hsa_queue_size(),
	};
	int ret;

	ret = amdxdna_drm_create_bo_ioctl(&client->xdna->ddev, &args, client->filp);
	if (ret)
		return ret;

	hwctx->umq_bo_hdl = args.handle;
	return 0;
}

static void ve2_hsa_queue_free(struct amdxdna_hwctx *hwctx)
{
	if (hwctx->umq_bo_hdl != AMDXDNA_INVALID_BO_HANDLE)
		drm_gem_handle_delete(hwctx->client->filp, hwctx->umq_bo_hdl);
}

/*
 * Host-queue completion (HQC) slots. CERT writes each command's final state
 * into its slot, in a driver-owned coherent buffer, because its store to the
 * ERT command BO can be dropped (observed after a partition reset). Once the
 * read index passes a command the driver copies the slot onto the command BO.
 * Only VE2 uses this, through the cmd_pkt_prepare and cmd_done hooks.
 */
struct ve2_hqc {
	struct amdxdna_msg_buf_hdl	*buf;
	u64				*slots;	/* CTX_MAX_CMDS entries */
	dma_addr_t			dma;
};

/* Per-context HQC state, keyed by the hwctx pointer. */
static DEFINE_XARRAY(ve2_hqc_xa);

static struct ve2_hqc *ve2_hqc_get(struct amdxdna_hwctx *hwctx)
{
	return xa_load(&ve2_hqc_xa, (unsigned long)hwctx);
}

/*
 * The first byte of a packet header is its HSA-style type. CERT consumes a
 * slot only while it is VENDOR_SPECIFIC, so VE2 keeps unpublished slots
 * INVALID. The aie4 header calls this byte "reserved"; other devices leave
 * it 0, which is VENDOR_SPECIFIC.
 */
#define VE2_PKT_TYPE_VENDOR_SPECIFIC	0
#define VE2_PKT_TYPE_INVALID		1

static void ve2_pkt_set_type(struct host_queue_packet *pkt, u8 type)
{
	WRITE_ONCE(*(u8 *)&pkt->pkt_header.common_header, type);
}

static bool ve2_hqc_state_terminal(enum ert_cmd_state state)
{
	return state == ERT_CMD_STATE_COMPLETED ||
	       state == ERT_CMD_STATE_ERROR ||
	       state == ERT_CMD_STATE_ABORT ||
	       state == ERT_CMD_STATE_TIMEOUT ||
	       state == ERT_CMD_STATE_NORESPONSE;
}

static u32 ve2_hqc_raw(struct ve2_hqc *hqc, u64 seq)
{
	/* Order the slot load after the caller's read_index check. */
	smp_rmb();
	return (u32)READ_ONCE(hqc->slots[seq & (CTX_MAX_CMDS - 1)]);
}

static bool ve2_hqc_seq_terminal(struct ve2_hqc *hqc, u64 seq)
{
	return ve2_hqc_state_terminal((enum ert_cmd_state)(ve2_hqc_raw(hqc, seq) & 0xF));
}

static void ve2_hqc_chain_error(struct amdxdna_hwctx *hwctx,
				struct amdxdna_sched_job *job,
				struct ve2_hqc *hqc, u64 seq)
{
	struct amdxdna_cmd_chain *cc = amdxdna_cmd_get_payload(job->cmd_bo, NULL);
	u32 fail_idx = 0;
	u32 count, i;

	if (!cc)
		return;

	count = cc->command_count;
	if (!count || count > seq + 1)
		return;

	for (i = count; i > 0; i--) {
		u64 sub_seq = seq - (count - i);
		enum ert_cmd_state st;

		st = (enum ert_cmd_state)(ve2_hqc_raw(hqc, sub_seq) & 0xF);
		if (ve2_hqc_state_terminal(st) && st != ERT_CMD_STATE_ABORT) {
			fail_idx = i - 1;
			break;
		}
	}

	cc->error_index = fail_idx;
	XDNA_ERR(hwctx->client->xdna, "%s chain failed at index %u", hwctx->name, fail_idx);
}

static void ve2_cmd_pkt_prepare(struct amdxdna_hwctx *hwctx, u32 slot,
				struct host_queue_packet *pkt)
{
	struct ve2_hqc *hqc = ve2_hqc_get(hwctx);

	if (!hqc)
		return;

	WRITE_ONCE(hqc->slots[slot], 0);
	pkt->pkt_header.completion_signal = hqc->dma + slot * sizeof(u64);
	/* The payload is complete: make the slot valid for CERT. */
	ve2_pkt_set_type(pkt, VE2_PKT_TYPE_VENDOR_SPECIFIC);
}

/*
 * read_index can move before CERT has stored the HQC slot, so wait briefly for
 * a terminal slot, then copy it onto the command BO. An empty slot is never
 * reported as COMPLETED: that would hide a command whose output never landed.
 */
static void ve2_cmd_done(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct ve2_hqc *hqc = ve2_hqc_get(hwctx);
	struct amdxdna_sched_job *job;
	enum ert_cmd_state state;
	ktime_t deadline;
	u32 raw;

	if (!hqc)
		return;

	if (!ve2_hqc_seq_terminal(hqc, seq)) {
		deadline = ktime_add_us(ktime_get(), 10000);
		while (!ve2_hqc_seq_terminal(hqc, seq) &&
		       ktime_before(ktime_get(), deadline))
			usleep_range(1, 20);
	}

	raw = ve2_hqc_raw(hqc, seq);
	state = (enum ert_cmd_state)(raw & 0xF);
	if (!ve2_hqc_state_terminal(state)) {
		static atomic_t reports = ATOMIC_INIT(0);

		if (atomic_inc_return(&reports) <= 32)
			XDNA_WARN(hwctx->client->xdna,
				  "%s seq %llu: HQC slot not terminal after 10 ms (raw 0x%x)",
				  hwctx->name, seq, raw);
		return;
	}

	mutex_lock(&priv->io_lock);
	list_for_each_entry(job, &priv->running_job_list, aie4_job_list) {
		if (job->seq != seq || job->aie4_job_state != AIE4_JOB_STATE_SUBMITTED)
			continue;

		if (state != ERT_CMD_STATE_COMPLETED) {
			static atomic_t reports = ATOMIC_INIT(0);

			if (atomic_inc_return(&reports) <= 32)
				XDNA_WARN(hwctx->client->xdna,
					  "%s seq %llu: CERT completed with state %u (raw 0x%x)",
					  hwctx->name, seq, state, raw);
		}
		/*
		 * A runlist is published as one packet per sub-command and
		 * job->seq is the last one. A failed chain reports its last
		 * slot, which does not say where it failed: CERT aborts the
		 * commands after the failing one, so the first non-ABORT slot
		 * scanning backwards is the failing index.
		 */
		if ((state == ERT_CMD_STATE_ERROR || state == ERT_CMD_STATE_ABORT) &&
		    amdxdna_cmd_get_op(job->cmd_bo) == ERT_CMD_CHAIN)
			ve2_hqc_chain_error(hwctx, job, hqc, seq);

		amdxdna_cmd_set_state(job->cmd_bo, state);
		/* Make the state visible before the job is completed. */
		smp_wmb();
		break;
	}
	mutex_unlock(&priv->io_lock);
}

static void ve2_hqc_free(struct ve2_hqc *hqc)
{
	if (!hqc)
		return;
	amdxdna_free_msg_buff(hqc->buf);
	kfree(hqc);
}

static int ve2_hqc_init(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct ve2_hqc *hqc;
	int i, ret;

	hqc = kzalloc_obj(*hqc);
	if (!hqc)
		return -ENOMEM;

	hqc->buf = amdxdna_alloc_msg_buff(hwctx->client->xdna,
					  CTX_MAX_CMDS * sizeof(u64));
	if (IS_ERR(hqc->buf)) {
		ret = PTR_ERR(hqc->buf);
		kfree(hqc);
		return ret;
	}
	hqc->slots = hqc->buf->vaddr;
	hqc->dma = hqc->buf->dma_addr;
	memset(hqc->slots, 0, CTX_MAX_CMDS * sizeof(u64));

	/* CERT consumes a slot only once it is made valid at publish. */
	for (i = 0; i < CTX_MAX_CMDS; i++)
		ve2_pkt_set_type(&priv->umq_pkts[i], VE2_PKT_TYPE_INVALID);

	ret = xa_err(xa_store(&ve2_hqc_xa, (unsigned long)hwctx, hqc, GFP_KERNEL));
	if (ret) {
		ve2_hqc_free(hqc);
		return ret;
	}
	return 0;
}

static int ve2_hwctx_init(struct amdxdna_hwctx *hwctx)
{
	int ret;

	ret = ve2_hsa_queue_alloc(hwctx);
	if (ret)
		return ret;

	ret = aie4_hwctx_init(hwctx);
	if (ret)
		goto free_queue;

	ret = ve2_hqc_init(hwctx);
	if (ret)
		goto fini_ctx;

	return 0;

fini_ctx:
	aie4_hwctx_fini(hwctx);
free_queue:
	ve2_hsa_queue_free(hwctx);
	return ret;
}

static void ve2_hwctx_fini(struct amdxdna_hwctx *hwctx)
{
	/* Keep the entry until aie4 has drained its jobs; cmd_done needs it. */
	aie4_hwctx_fini(hwctx);
	ve2_hqc_free(xa_erase(&ve2_hqc_xa, (unsigned long)hwctx));
	ve2_hsa_queue_free(hwctx);
}

/*
 * The doorbell is addressed by priv->hw_ctx_id; register the aie4-owned
 * queue indices with the VE2 transport so a shared partition can schedule
 * this context without changing the aie4 command path.
 */
int aie4_doorbell_setup(struct amdxdna_hwctx *hwctx,
			const struct aie4_msg_create_hw_context_resp *resp)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_hwctx_priv *priv = hwctx->priv;

	return ve2_mbox_bind_ctx(ndev->mbox, resp->hw_context_id,
				 priv->umq_read_index, &priv->write_index);
}

void aie4_doorbell_ring(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	ret = ve2_mbox_ring_doorbell(ndev->mbox, hwctx->priv->hw_ctx_id);
	if (ret)
		XDNA_ERR(xdna, "ctx %s doorbell failed: %d", hwctx->name, ret);
}

static void ve2_cert_comp_notify(void *data)
{
	struct cert_comp *comp = data;

	wake_up_all(&comp->waitq);
}

int aie4_request_notification(struct cert_comp *comp)
{
	return ve2_mbox_attach_notify(comp->ndev->mbox, comp->msix_idx,
				      ve2_cert_comp_notify, comp);
}

void aie4_free_notification(struct cert_comp *comp)
{
	ve2_mbox_detach_notify(comp->ndev->mbox, comp->msix_idx);
}

bool aie4_is_vf(struct amdxdna_dev_hdl *ndev)
{
	return false;
}

int aie4_set_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level)
{
	return 0;
}

void aie4_update_counters(struct amdxdna_dev_hdl *ndev)
{
}

static int ve2_mailbox_init(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret;

	ndev->mbox = xdnam_mailbox_create(&xdna->ddev, NULL);
	if (IS_ERR(ndev->mbox)) {
		ret = PTR_ERR(ndev->mbox);
		ndev->mbox = NULL;
		XDNA_ERR(xdna, "failed to create VE2 mailbox, ret %d", ret);
		return ret;
	}

	ndev->aie.mgmt_chann = xdna_mailbox_alloc_channel(ndev->mbox);
	if (!ndev->aie.mgmt_chann) {
		XDNA_ERR(xdna, "failed to alloc mailbox channel");
		return -ENODEV;
	}

	xdna_mailbox_set_async_cb(ndev->aie.mgmt_chann, ndev,
				  aie4_mgmt_async_event_handler);

	ret = xdna_mailbox_start_channel(ndev->aie.mgmt_chann, NULL, NULL, 0, 0, 0);
	if (ret) {
		xdna_mailbox_free_channel(ndev->aie.mgmt_chann);
		ndev->aie.mgmt_chann = NULL;
	}
	return ret;
}

static void ve2_mailbox_fini(struct amdxdna_dev_hdl *ndev)
{
	if (!ndev->aie.mgmt_chann)
		return;

	xdna_mailbox_stop_channel(ndev->aie.mgmt_chann);
	xdna_mailbox_free_channel(ndev->aie.mgmt_chann);
	ndev->aie.mgmt_chann = NULL;
}

static int ve2_init(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev;
	int ret;

	ndev = drmm_kzalloc(&xdna->ddev, sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		return -ENOMEM;

	ndev->aie.xdna = xdna;
	xdna->dev_handle = ndev;
	ndev->kernel_submit = true;

	xa_init_flags(&ndev->cert_comp_xa, XA_FLAGS_ALLOC);
	mutex_init(&ndev->cert_comp_lock);

	ret = ve2_mailbox_init(ndev);
	if (ret)
		goto xa_fini;

	ret = ve2_mbox_load_fw(ndev->mbox);
	if (ret)
		goto mbox_fini;

	/*
	 * Same feature negotiation as the platform path: IDENTIFY plus the
	 * CERT version turn on AIE4_HSA_COMMAND, which aie4_hwctx_init()
	 * requires. Skip the platform work-buffer attach; that opcode is not
	 * implemented here and VE2 CERT does not use the buffer.
	 */
	ret = aie4_query_fw(ndev);
	if (ret)
		goto mbox_fini;

	ndev->aie.fw_prot_major = xdna->fw_ver.major;
	ndev->aie.fw_prot_minor = xdna->fw_ver.minor;
	ret = aie_check_protocol(&ndev->aie);
	if (ret) {
		XDNA_ERR(xdna, "firmware %u.%u is not supported",
			 xdna->fw_ver.major, xdna->fw_ver.minor);
		goto mbox_fini;
	}

	ret = aie4_setup_aie(ndev);
	if (ret)
		goto mbox_fini;

	ret = ve2_mbox_set_max_cols(ndev->mbox, ve2_max_col);
	if (ret) {
		XDNA_ERR(xdna, "invalid max_col %d for %u-column AIE, ret %d",
			 ve2_max_col, ndev->total_col, ret);
		goto mbox_fini;
	}
	if (ve2_max_col) {
		ndev->total_col = ve2_max_col;
		XDNA_INFO(xdna, "VE2 allocator limited to %u columns", ndev->total_col);
	}

	aie4_msg_init(ndev);
	amdxdna_dpt_init(&ndev->aie);
	amdxdna_pm_init(xdna);
	amdxdna_vbnv_init(xdna);
	return 0;

mbox_fini:
	ve2_mailbox_fini(ndev);
xa_fini:
	mutex_destroy(&ndev->cert_comp_lock);
	xa_destroy(&ndev->cert_comp_xa);
	return ret;
}

static void ve2_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	if (!ndev)
		return;

	amdxdna_pm_fini(xdna);
	amdxdna_dpt_fini(&ndev->aie);
	ve2_mailbox_fini(ndev);
	ve2_mbox_release(ndev->mbox);
	amdxdna_async_events_free(&ndev->aie);
	mutex_destroy(&ndev->cert_comp_lock);
	xa_destroy(&ndev->cert_comp_xa);
}

static int ve2_suspend(struct amdxdna_dev *xdna)
{
	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	aie4_hwctx_suspend_all(xdna->dev_handle, false);
	return 0;
}

static int ve2_resume(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	ret = aie4_hwctx_resume_all(ndev);
	if (ret) {
		XDNA_ERR(xdna, "hwctx resume failed, %d", ret);
		aie4_hwctx_suspend_all(ndev, true);
	}
	return ret;
}

const struct amdxdna_dev_ops ve2_ops = {
	.init			= ve2_init,
	.fini			= ve2_fini,
	.debugfs_init		= aie4_debugfs_init,
	.hwctx_init		= ve2_hwctx_init,
	.hwctx_fini		= ve2_hwctx_fini,
	.hwctx_config		= aie4_hwctx_config,
	.cmd_submit		= aie4_cmd_submit,
	.cmd_wait		= aie4_cmd_wait,
	.cmd_pkt_prepare	= ve2_cmd_pkt_prepare,
	.cmd_done		= ve2_cmd_done,
	.get_aie_info		= aie4_get_info,
	.set_aie_state		= aie4_set_state,
	.get_array		= aie4_get_array,
	.resume			= ve2_resume,
	.suspend		= ve2_suspend,
	.runtime_resume		= ve2_resume,
	.runtime_suspend	= ve2_suspend,
	.handle_dev_async_event	= aie4_handle_dev_event,
};
