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
#include <linux/minmax.h>
#include <linux/overflow.h>
#include <linux/sched/mm.h>
#include <linux/timekeeping.h>
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
#include "amdxdna_pm.h"
#include "trace/events/amdxdna.h"

#define CTX_INVALID_ID			(~0U)
#define CTX_INVALID_DOORBELL		AMDXDNA_INVALID_DOORBELL_OFFSET

static void job_worker(struct work_struct *work);

static struct cert_comp *aie4_lookup_cert_comp(struct amdxdna_dev_hdl *ndev, u32 msix_idx)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
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
		return ERR_PTR(-ENOMEM);

	cert_comp->ndev = ndev;
	cert_comp->msix_idx = msix_idx;
	cert_comp->irq = -ENOENT;
	init_waitqueue_head(&cert_comp->waitq);
	kref_init(&cert_comp->kref);

	/* Transport-specific: PCI wires an MSI-X irq, platform an IPI callback. */
	ret = aie4_request_notification(cert_comp);
	if (ret) {
		XDNA_ERR(xdna, "request notification for msix idx %u failed %d", msix_idx, ret);
		goto free_cert_comp;
	}

	ret = xa_err(xa_store(&ndev->cert_comp_xa, msix_idx, cert_comp, GFP_KERNEL));
	if (ret) {
		XDNA_ERR(xdna, "store cert_comp for msix idx %u failed %d", msix_idx, ret);
		goto free_irq;
	}

	return cert_comp;

free_irq:
	aie4_free_notification(cert_comp);
free_cert_comp:
	kfree(cert_comp);
	return ERR_PTR(ret);
}

static void cert_comp_release(struct kref *kref)
{
	struct cert_comp *cert_comp = container_of(kref, struct cert_comp, kref);
	struct amdxdna_dev_hdl *ndev = cert_comp->ndev;

	xa_erase(&ndev->cert_comp_xa, cert_comp->msix_idx);
	aie4_free_notification(cert_comp);
	kfree(cert_comp);
}

static void aie4_put_cert_comp(struct cert_comp *cert_comp)
{
	struct amdxdna_dev_hdl *ndev = cert_comp->ndev;

	guard(mutex)(&ndev->cert_comp_lock);

	kref_put(&cert_comp->kref, cert_comp_release);
}

static struct cert_comp *aie4_get_cert_comp(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct cert_comp *cert_comp;

	/*
	 * priv->cert_comp is the per-hwctx field, guarded by io_lock.  A non-NULL
	 * value means this ctx still holds its link-ref, so the object is alive and
	 * the kref_get here cannot race the free (which only happens once the field
	 * is cleared under io_lock in aie4_hwctx_destroy()).
	 */
	guard(mutex)(&priv->io_lock);

	cert_comp = priv->cert_comp;
	if (cert_comp)
		kref_get(&cert_comp->kref);

	return cert_comp;
}

static void aie4_msg_destroy_context(struct amdxdna_dev_hdl *ndev, u32 hw_context_id)
{
	DECLARE_AIE_MSG(aie4_msg_destroy_hw_context, AIE4_MSG_OP_DESTROY_HW_CONTEXT);
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret;

	req.hw_context_id = hw_context_id;
	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_WARN(xdna, "destroy ctx id %d failed %d", hw_context_id, ret);
}

static u32 aie4_parse_priority_to_dev(u32 priority)
{
	switch (priority) {
	case AMDXDNA_QOS_LOW_PRIORITY:
		return AIE4_CONTEXT_PRIORITY_BAND_IDLE;
	case AMDXDNA_QOS_NORMAL_PRIORITY:
		return AIE4_CONTEXT_PRIORITY_BAND_NORMAL;
	case AMDXDNA_QOS_HIGH_PRIORITY:
		return AIE4_CONTEXT_PRIORITY_BAND_FOCUS;
	case AMDXDNA_QOS_REALTIME_PRIORITY:
		return AIE4_CONTEXT_PRIORITY_BAND_REAL_TIME;
	default:
		return AIE4_CONTEXT_PRIORITY_BAND_NORMAL;
	}
}

int aie4_hwctx_create(struct amdxdna_hwctx *hwctx)
{
	DECLARE_AIE_MSG(aie4_msg_create_hw_context, AIE4_MSG_OP_CREATE_HW_CONTEXT);
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct cert_comp *cert_comp;
	int ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (!ndev->partition_id || !hwctx->num_tiles) {
		XDNA_ERR(xdna, "invalid request partition_id %u, num_tiles %d",
			 ndev->partition_id, hwctx->num_tiles);
		return -EINVAL;
	}

	req.partition_id = ndev->partition_id;
	req.request_num_tiles = hwctx->num_tiles;
	req.pasid = aie4_msg_pasid(client);
	req.priority_band = aie4_parse_priority_to_dev(hwctx->qos.priority);
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
		 resp.job_complete_msix_idx, resp.hw_context_id,
		 resp.doorbell_offset);

	/* setup interrupt completion per msix index */
	cert_comp = aie4_lookup_cert_comp(ndev, resp.job_complete_msix_idx);
	if (IS_ERR(cert_comp)) {
		aie4_msg_destroy_context(ndev, resp.hw_context_id);
		return PTR_ERR(cert_comp);
	}

	priv->hw_ctx_id = resp.hw_context_id;

	/*
	 * Mirror the firmware hardware context id onto the common hwctx so the
	 * shared status/telemetry paths can key on it. Unlike AIE2, firmware
	 * does not hand back a per-context column range; every context runs in
	 * the single device-wide partition (aie4_partition_init: col_start 0,
	 * AIE4_TOTAL_COLUMN wide) which the firmware time-shares, so report that
	 * partition span. This gives amdxdna_drm_hwctx_entry a real hwctx_id and
	 * a non-empty column list for the aie-partitions view.
	 */
	hwctx->fw_ctx_id = resp.hw_context_id;
	hwctx->start_col = 0;
	hwctx->num_col = ndev->total_col;

	if (priv->kernel_submit) {
		/*
		 * Kernel-mode submission: set up this context's doorbell kick target
		 * (transport-specific, via aie4_doorbell_setup) so the driver can ring
		 * it, and keep it out of user space (hand back an invalid offset so the
		 * doorbell cannot be mmap'd/rung by the user).
		 *
		 * Publish under io_lock so a concurrent submitter - which reads the
		 * connected sentinel and rings the doorbell under io_lock - cannot, on a
		 * TDR recreate of a live ctx, observe a torn or stale kick target.
		 * priv->cert_comp is the connected sentinel; publish it last, after the
		 * doorbell is set up, so a submitter that observes the ctx connected also
		 * sees a valid doorbell.
		 */
		mutex_lock(&priv->io_lock);
		ret = aie4_doorbell_setup(hwctx, &resp);
		if (ret) {
			mutex_unlock(&priv->io_lock);
			aie4_put_cert_comp(cert_comp);
			aie4_msg_destroy_context(ndev, resp.hw_context_id);
			/* Match a clean teardown so a later fini does not re-destroy. */
			priv->hw_ctx_id = CTX_INVALID_ID;
			hwctx->fw_ctx_id = -1;
			return ret;
		}
		WRITE_ONCE(priv->has_reset, false);
		/*
		 * Consume the cached ctx-error report on (re)connect. The faulting
		 * job (if any) already read it during the reset drain; clearing here
		 * also covers a reset that timed out nothing (empty running list), so
		 * a later unrelated reset cannot observe a stale report. It also
		 * doubles as the "faulting job already timed out" marker for the drain
		 * (see job_worker), so the next reset starts from a clean slate.
		 */
		priv->cached_ctx_error_valid = false;
		/* Publish the connected sentinel last (see comment above). */
		WRITE_ONCE(priv->cert_comp, cert_comp);
		mutex_unlock(&priv->io_lock);
		hwctx->doorbell_offset = CTX_INVALID_DOORBELL;
		wake_up_all(&priv->job_list_wq);
	} else {
		/* User-mode submission: hand the doorbell to user space to ring. */
		mutex_lock(&priv->io_lock);
		WRITE_ONCE(priv->cert_comp, cert_comp);
		mutex_unlock(&priv->io_lock);
		hwctx->doorbell_offset = resp.doorbell_offset;
	}

	return 0;
}

/*
 * The connected sentinel for the submit wait gate: a linked cert_comp means the
 * ctx is created and (for kernel submission) its doorbell is set up.  Read
 * locklessly (a pointer null-check, never a dereference); create publishes it as
 * the last store under io_lock and destroy clears it first, so "connected"
 * implies a valid doorbell.
 */
static bool aie4_hwctx_connected(struct amdxdna_hwctx *hwctx)
{
	return !!READ_ONCE(hwctx->priv->cert_comp);
}

static bool aie4_hwctx_has_reset(struct amdxdna_hwctx *hwctx)
{
	return READ_ONCE(hwctx->priv->has_reset);
}

void aie4_hwctx_destroy(struct amdxdna_hwctx *hwctx, enum aie4_hwctx_flags flags)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct cert_comp *cert_comp;
	bool has_reset = false;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	if (flags == AIE4_HWCTX_DISCONNECT || flags == AIE4_HWCTX_ERROR)
		has_reset = true;

	/*
	 * Disconnect: latch the reset reason and clear priv->cert_comp (the
	 * connected sentinel) together under io_lock - the field's lock - then wake
	 * completion waiters and drop the ref.  Clearing the field first (before
	 * tearing down the firmware context) makes a waiter on cert_comp->waitq
	 * observe the disconnect and retry (-EAGAIN) rather than mistaking it for
	 * completion, and the submit gate reads the ctx as disconnected.  has_reset
	 * is set before the wake so a worker parked in wait_till_seq_completed()
	 * takes the drain path rather than re-parking its in-flight job.  The
	 * kref_put runs under cert_comp_lock (aie4_put_cert_comp).
	 */
	mutex_lock(&priv->io_lock);
	if (has_reset)
		WRITE_ONCE(priv->has_reset, true);
	cert_comp = priv->cert_comp;
	WRITE_ONCE(priv->cert_comp, NULL);
	mutex_unlock(&priv->io_lock);

	if (cert_comp) {
		wake_up_all(&cert_comp->waitq);
		aie4_put_cert_comp(cert_comp);
	}

	/*
	 * On a reset, wake any submitter parked in
	 * wait_till_connected_hsa_not_full(). One that has already published a
	 * prefix observes has_reset and unwinds with -ECONNRESET rather than
	 * waiting for the recreate (which runs after aie4_hwctx_wait_for_running()),
	 * so it releases pending_head. A first-command submitter (nothing
	 * published) instead re-checks and keeps waiting for the recreate; it is
	 * PENDING, so wait_for_running() does not block on it.
	 */
	if (priv->kernel_submit && has_reset)
		wake_up_all(&priv->job_list_wq);

	if (flags != AIE4_HWCTX_DISCONNECT)
		aie4_msg_destroy_context(ndev, priv->hw_ctx_id);

	priv->hw_ctx_id = CTX_INVALID_ID;
	hwctx->fw_ctx_id = -1;
	hwctx->doorbell_offset = CTX_INVALID_DOORBELL;

	/*
	 * On a non-reset teardown (NORMAL suspend / fini), quiesce the worker so
	 * running_job_list is stable for aie4_hwctx_resume_jobs() (suspend) or the
	 * fini abort loop. The worker observes the disconnect (cert_comp unlinked
	 * and its waitq woken above), re-parks its in-flight job at the head of
	 * running_job_list, and returns, so cancel_work_sync() completes rather
	 * than blocking.
	 *
	 * On a reset (ERROR/DISCONNECT, has_reset set) do NOT cancel the worker:
	 * it must stay live to drain the list (timeout head, abort rest), which
	 * aie4_hwctx_wait_for_running() waits out before the ctx is recreated.
	 */
	if (priv->kernel_submit && !has_reset)
		cancel_work_sync(&priv->job_work);
}

/*
 * Fill @cmd_abo's data region with the cached aie4 context health report as a
 * struct amdxdna_ctx_health_data (version 1) so user space can read it after
 * the command is marked timed out. If no report was cached for this context,
 * the per-generation fields are zeroed. The cached report is not consumed here:
 * the job worker's reset path (aie4_hwctx_has_reset) attaches it to the faulting
 * head job and clears it exactly once after that job is timed out, so a later
 * unrelated reset cannot observe a stale report. Caller must hold
 * io_lock, which serializes this multi-word read against the async error worker
 * overwriting the cache concurrently.
 */
static void aie4_fill_health_data_locked(struct amdxdna_gem_obj *cmd_abo,
					 struct amdxdna_hwctx *hwctx)
{
	const size_t min_size = offsetof(struct amdxdna_ctx_health_data, aie4.uc_info);
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct aie4_msg_app_health_report *report;
	struct amdxdna_ctx_health_data *health;
	u32 data_total;

	health = amdxdna_cmd_get_data(cmd_abo, &data_total);
	if (!health || data_total < min_size) {
		XDNA_WARN(xdna, "Health data buffer too small: %u min %zu",
			  data_total, min_size);
		return;
	}

	health->version = AMDXDNA_CTX_HEALTH_DATA_V1;
	health->npu_gen = AMDXDNA_NPU_GEN_AIE4;
	health->aie4.ctx_state = 0;
	health->aie4.num_uc = 0;
	health->aie4.ctx_error_type = 0;
	/*
	 * Zero the uc_info tail up front so an empty (no cached report) or
	 * partial (num_uc < capacity) result never exposes stale bytes from the
	 * caller's command BO. Bounded by both the BO's available room and the
	 * field size.
	 */
	memset(health->aie4.uc_info, 0,
	       min_t(u32, data_total - min_size, sizeof(health->aie4.uc_info)));

	if (!priv->cached_ctx_error_valid)
		return;

	report = &priv->cached_ctx_error.app_health_report;
	health->aie4.ctx_state = FIELD_GET(AIE4_APP_HEALTH_CTX_STATUS, report->ctx_num_uc);
	health->aie4.ctx_error_type = priv->cached_ctx_error.error_type;

	if (data_total > min_size) {
		u32 max_uc = (data_total - min_size) / sizeof(struct uc_health_info);
		u32 num_uc = FIELD_GET(AIE4_APP_HEALTH_NUM_UC, report->ctx_num_uc);

		/*
		 * Bound by the fixed firmware source array (report->uc_info has
		 * AIE4_MPNPUFW_MAX_UC_COUNT entries) as well as the user buffer
		 * capacity, so a firmware-reported count cannot drive an
		 * out-of-bounds read of the source or write of the destination.
		 */
		num_uc = min_t(u32, num_uc, AIE4_MPNPUFW_MAX_UC_COUNT);
		num_uc = min_t(u32, num_uc, max_uc);
		if (num_uc)
			memcpy(health->aie4.uc_info, report->uc_info,
			       num_uc * sizeof(struct uc_health_info));
		health->aie4.num_uc = num_uc;
	}
}

/*
 * Fill a command's data region with this context's cached health report. Helper
 * for the kernel-mode timeout/recovery (TDR) path to call on a failing command;
 * the TDR detection and recovery mechanism itself is not implemented here.
 */
void aie4_fill_health_data(struct amdxdna_gem_obj *cmd_abo, struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;

	mutex_lock(&priv->io_lock);
	aie4_fill_health_data_locked(cmd_abo, hwctx);
	mutex_unlock(&priv->io_lock);
}

static void aie4_hwctx_umq_fini(struct amdxdna_hwctx *hwctx)
{
	if (hwctx->priv && hwctx->priv->umq_bo)
		drm_gem_object_put(to_gobj(hwctx->priv->umq_bo));
}

static int aie4_hwctx_umq_init(struct amdxdna_hwctx *hwctx)
{
	const size_t indir_pkts_sz = CTX_MAX_CMDS * HSA_MAX_LEVEL1_INDIRECT_ENTRIES *
				     sizeof(struct host_indirect_packet_data);
	const size_t pkts_sz = CTX_MAX_CMDS * sizeof(struct host_queue_packet);
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_gem_obj *umq_bo;
	struct host_queue_header *qhdr;
	u64 data_dev_addr;
	void *umq_va;
	int ret;
	int i;

	/*
	 * The HSA queue lives in a user-allocated BO (umq_bo_hdl) in both user- and
	 * kernel-mode submission; the driver does not allocate it privately.  Under
	 * PASID/SVA the device reaches the queue through the submitting process's
	 * own page tables, so it must have a user virtual address - a kernel-private
	 * buffer would be unreachable by the device.  This is also safe: a forged
	 * read_index in this shared BO can only make the owning process complete its
	 * own command early and harm itself, never another context (NO_PASID/IOVA is
	 * a single-trust bring-up mode with no inter-process isolation).
	 */
	umq_bo = amdxdna_gem_get_obj(hwctx->client, hwctx->umq_bo_hdl, AMDXDNA_BO_SHARE);
	if (!umq_bo) {
		XDNA_ERR(xdna, "cannot find umq_bo handle %d", hwctx->umq_bo_hdl);
		return -ENOENT;
	}
	priv->umq_bo = umq_bo;

	/*
	 * Kernel-mode submission: the driver fills the host queue and rings the
	 * doorbell, so the user umq_bo must hold the header plus the direct and
	 * level-1 indirect packet arrays.  User-mode submission only needs the
	 * header (the user owns the queue content).
	 */
	if (umq_bo->mem.size < sizeof(*qhdr) ||
	    (priv->kernel_submit &&
	     umq_bo->mem.size < sizeof(*qhdr) + pkts_sz + indir_pkts_sz)) {
		XDNA_ERR(xdna, "umq_bo size %zu is too small",
			 (size_t)umq_bo->mem.size);
		ret = -EINVAL;
		goto err_fini;
	}

	umq_va = amdxdna_gem_vmap(umq_bo);
	if (!umq_va) {
		ret = -ENOMEM;
		goto err_fini;
	}
	qhdr = umq_va;

	priv->umq_read_index = &qhdr->read_index;
	priv->umq_write_index = &qhdr->write_index;

	/* User-mode submission: user owns the queue content and the doorbell. */
	if (!priv->kernel_submit)
		return 0;

	/*
	 * The queue content is driver-owned and never trusted from user space
	 * (only read_index is read back to detect completion).  Lay out the
	 * direct packets right after the header and the indirect packets after
	 * them, and publish the same base via data_address for CERT.
	 */
	data_dev_addr = amdxdna_gem_dev_addr(umq_bo) + sizeof(*qhdr);
	priv->umq_pkts = umq_va + sizeof(*qhdr);
	priv->umq_indirect_pkts = umq_va + sizeof(*qhdr) + pkts_sz;
	priv->umq_indirect_pkts_dev_addr = data_dev_addr + pkts_sz;

	/*
	 * Only the header + direct/indirect packet regions are driver-owned and
	 * used for kernel submission; the size check above guarantees they fit.
	 * Clear just that range, not the whole user-sized BO, so an oversized
	 * umq_bo cannot force a huge memset (and page faults) under dev_lock.
	 */
	memset(umq_va, 0, sizeof(*qhdr) + pkts_sz + indir_pkts_sz);
	priv->write_index = QUEUE_INDEX_START;
	qhdr->read_index = QUEUE_INDEX_START;
	qhdr->write_index = QUEUE_INDEX_START;
	qhdr->version.major = HOST_QUEUE_MAJOR_VERSION;
	qhdr->version.minor = HOST_QUEUE_MINOR_VERSION;
	qhdr->capacity = CTX_MAX_CMDS;
	qhdr->data_address = data_dev_addr;
	for (i = 0; i < CTX_MAX_CMDS; i++)
		priv->umq_pkts[i].pkt_header.common_header.opcode = OPCODE_EXEC_BUF;
	for (i = 0; i < CTX_MAX_CMDS * HSA_MAX_LEVEL1_INDIRECT_ENTRIES; i++) {
		priv->umq_indirect_pkts[i].header.opcode = OPCODE_EXEC_BUF;
		priv->umq_indirect_pkts[i].header.count = sizeof(struct exec_buf);
		priv->umq_indirect_pkts[i].header.distribute = 1;
	}

	return 0;

err_fini:
	aie4_hwctx_umq_fini(hwctx);
	return ret;
}

int aie4_hwctx_init(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_hwctx_priv *priv;
	int ret;

	if (!AIE_FEATURE_ON(&ndev->aie, AIE4_HSA_COMMAND))
		return -EOPNOTSUPP;

	priv = kzalloc_obj(*priv);
	if (!priv)
		return -ENOMEM;
	hwctx->priv = priv;
	priv->hwctx = hwctx;
	/*
	 * Snapshot the device's kernel-mode submission setting (debugfs-tunable)
	 * so it is stable for this ctx's lifetime.
	 */
	priv->kernel_submit = ndev->kernel_submit;

	/*
	 * io_lock guards the per-hwctx cert_comp binding (the connected sentinel)
	 * for every ctx, so initialize it unconditionally.  kzalloc left cert_comp
	 * NULL: disconnected until create links it.
	 */
	mutex_init(&priv->io_lock);

	/*
	 * Kernel-mode submission: the driver fills the queue and rings the
	 * doorbell, so it needs the job machinery.  User-mode submission leaves
	 * the queue and doorbell to user space (no job machinery here).
	 */
	if (priv->kernel_submit) {
		INIT_LIST_HEAD(&priv->pending_job_list);
		INIT_LIST_HEAD(&priv->running_job_list);
		init_waitqueue_head(&priv->job_list_wq);
		INIT_WORK(&priv->job_work, job_worker);
		priv->job_work_q = alloc_ordered_workqueue("%s", 0, hwctx->name);
		if (!priv->job_work_q) {
			XDNA_ERR(xdna, "Create job_work_q failed");
			ret = -ENOMEM;
			goto destroy_lock;
		}
	}

	ret = aie4_hwctx_umq_init(hwctx);
	if (ret)
		goto destroy_wq;

	/*
	 * Resume the device so aie4_hwctx_create() can reach firmware; the create
	 * ioctl holds dev_lock, so use the _locked variant. Drop the ref right
	 * after: the context does not need the device resumed for its lifetime.
	 */
	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto umq_fini;

	ret = aie4_hwctx_create(hwctx);
	amdxdna_pm_suspend_put(xdna);
	if (ret)
		goto umq_fini;

	XDNA_DBG(xdna, "hwctx %s init completed (%s submission)", hwctx->name,
		 priv->kernel_submit ? "kernel" : "user");
	return 0;

umq_fini:
	aie4_hwctx_umq_fini(hwctx);
destroy_wq:
	if (priv->kernel_submit)
		destroy_workqueue(priv->job_work_q);
destroy_lock:
	mutex_destroy(&priv->io_lock);
	kfree(priv);
	hwctx->priv = NULL;
	return ret;
}

void aie4_hwctx_fini(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;

	/*
	 * ERROR sets has_reset (like a TDR reset) so the worker drains the running
	 * list - the ctx is gone, so in-flight jobs are reaped - and stays live
	 * for aie4_hwctx_wait_for_running() to wait on. Submitters are already gone
	 * (amdxdna_hwctx_destroy_rcu() synchronize_srcu'd them out), then the
	 * queue is torn down.
	 */
	aie4_hwctx_destroy(hwctx, AIE4_HWCTX_ERROR);
	if (priv->kernel_submit) {
		aie4_hwctx_wait_for_running(hwctx);
		destroy_workqueue(priv->job_work_q);
	}
	aie4_hwctx_umq_fini(hwctx);
	mutex_destroy(&priv->io_lock);
	kfree(priv);
}

static inline bool valid_queue_index(u64 read, u64 write, u32 capacity)
{
	return (write >= read) && ((write - read) <= capacity);
}

static u64 get_read_index(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u64 ri, wi;

	/*
	 * Sample read_index (written by CERT) before write_index. CERT can
	 * never complete more than has been published, so a write_index sampled
	 * after read_index always satisfies wi >= ri; sampling write_index
	 * first races the submit path / CERT and yields a bogus ri > wi.
	 *
	 * In kernel-mode submission write_index is the driver's host-owned copy
	 * in coherent kernel memory (always >= the value mirrored into the UMQ,
	 * and the device never writes it).  In user-mode submission the user
	 * owns the queue, so fall back to the shared UMQ copy.
	 *
	 * Security: read_index lives in the umq_bo, which the owning process can
	 * map.  Under PASID/SVA the device reaches the queue through that process's
	 * own page tables, so a forged read_index only completes the process's own
	 * command early and corrupts or hangs itself - it cannot reach another
	 * context.
	 */
	ri = READ_ONCE(*priv->umq_read_index);
	/* Order the read_index sample before the write_index sample. */
	smp_rmb();
	wi = priv->kernel_submit ? READ_ONCE(priv->write_index)
				 : READ_ONCE(*priv->umq_write_index);

	/*
	 * CERT cannot update read index as uint64 atomically. Driver may read
	 * a half-updated read index when it has bits in the high 32 bits. If it
	 * looks invalid, re-sample once -- WITHOUT sleeping, since this can run as
	 * a wait_event() condition. If still invalid, report not-advanced; the
	 * waiter re-checks on the next completion wake or timeout.
	 */
	if (!valid_queue_index(ri, wi, CTX_MAX_CMDS)) {
		ri = READ_ONCE(*priv->umq_read_index);
		/* Order the read_index sample before the write_index sample. */
		smp_rmb();
		wi = priv->kernel_submit ? READ_ONCE(priv->write_index)
					 : READ_ONCE(*priv->umq_write_index);
		if (!valid_queue_index(ri, wi, CTX_MAX_CMDS)) {
			/*
			 * Still invalid (torn 64-bit read, or a transient
			 * accounting skew).  Return the last valid read_index
			 * instead of 0: read_index only advances, so the cached
			 * value is a safe lower bound -- it never reports a
			 * command complete that isn't, and never regresses the
			 * worker into falsely timing out a finished job.
			 */
			XDNA_DBG(xdna, "Invalid index, ri %llu, wi %llu", ri, wi);
			return READ_ONCE(priv->last_read_index);
		}
	}

	WRITE_ONCE(priv->last_read_index, ri);
	return ri;
}

/*
 * The ctx is "connected" as long as @comp is still the cert_comp linked to it.
 * A disconnect (teardown/reset) unlinks (and may re-link a fresh) cert_comp, so
 * a changed pointer means the caller must retry (-EAGAIN).  This runs as a
 * wait_event() condition on the completion hot path (cert_comp->waitq is shared
 * per MSI-X), so keep it lockless: the caller pins @comp with a kref, making
 * this a pure pointer-identity compare - never a dereference, ABA-safe - and
 * READ_ONCE pairs with the WRITE_ONCE in aie4_hwctx_create()/
 * aie4_hwctx_destroy().
 */
static bool check_cert_comp_linked(struct amdxdna_hwctx *hwctx, struct cert_comp *comp)
{
	/* READ_ONCE pairs with the link/unlink WRITE_ONCE. */
	return comp == READ_ONCE(hwctx->priv->cert_comp);
}

static bool check_cmd_done(struct amdxdna_hwctx *hwctx, u64 seq, struct cert_comp *comp)
{
	/*
	 * Runs as a wait_event() condition, so it must not sleep.
	 * check_cert_comp_linked() is lockless (a READ_ONCE pointer compare); a
	 * disconnect (teardown/reset) unlinks @comp and breaks the wait, and the
	 * caller then confirms real completion by re-reading read_index, so a
	 * disconnect wake is not mistaken for success.
	 */
	if (!check_cert_comp_linked(hwctx, comp))
		return true;

	return get_read_index(hwctx) > seq;
}

int aie4_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout)
{
	unsigned long wait_jifs = MAX_SCHEDULE_TIMEOUT;
	struct cert_comp *cert_comp = aie4_get_cert_comp(hwctx);
	long ret;

	if (!cert_comp)
		return -EAGAIN;

	if (timeout)
		wait_jifs = msecs_to_jiffies(timeout);

	ret = wait_event_interruptible_timeout(cert_comp->waitq,
					       check_cmd_done(hwctx, seq, cert_comp),
					       wait_jifs);

	if (!ret)
		ret = -ETIME;
	else if (ret > 0 && get_read_index(hwctx) <= seq)
		/* Woke on disconnect/reset, not on real completion. */
		ret = -EAGAIN;

	aie4_put_cert_comp(cert_comp);

	return ret <= 0 ? ret : 0;
}

/* ---- kernel-mode submission (driver fills the queue and rings doorbell) ---- */

/* Publish a command to CERT and return the assigned command sequence (slot). */
static u64 publish_cmd(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	u64 wi = priv->write_index;

	/* Paired with the lockless READ_ONCE() readers of write_index. */
	WRITE_ONCE(priv->write_index, wi + 1);
	/* Order the packet-slot writes before CERT sees the new write_index. */
	wmb();
	WRITE_ONCE(*priv->umq_write_index, wi + 1);
	return wi;
}

static int wait_till_seq_completed(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct cert_comp *cert_comp;
	int ret;

	/*
	 * Freezable + interruptible: the submit path (wait_till_connected_hsa_not_full)
	 * reaches here while holding hwctx_srcu, and ctx teardown blocks on
	 * synchronize_srcu(), so a signal (e.g. the app being killed) must be
	 * able to unwind the wait - otherwise a full queue with a silent CERT
	 * would hang the submitter in D state and stall teardown forever.
	 * TASK_FREEZABLE lets the freezer suspend this wait in place during
	 * S3/S4 instead of aborting the suspend.  Harmless for the job worker
	 * kthread (never gets a signal; simply freezes/thaws around it).
	 */
	cert_comp = aie4_get_cert_comp(hwctx);
	if (!cert_comp)
		return -EAGAIN;

	ret = wait_event_freezable(cert_comp->waitq,
				   check_cmd_done(hwctx, seq, cert_comp));
	if (ret) {
		aie4_put_cert_comp(cert_comp);
		return ret;	/* -ERESTARTSYS: signal on the submit path */
	}

	if (check_cert_comp_linked(hwctx, cert_comp))
		ret = 0;			/* real completion */
	else
		ret = -EAGAIN;			/* disconnect (suspend or TDR) */

	aie4_put_cert_comp(cert_comp);
	return ret;
}

static int wait_till_connected_hsa_not_full(struct amdxdna_hwctx *hwctx,
					    bool wait_through_reset)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	u64 wi = READ_ONCE(priv->write_index);
	bool hsa_not_full = !!(wi < CTX_MAX_CMDS);
	int ret;

	do {
		mutex_unlock(&priv->io_lock);
		if (!hsa_not_full) {
			ret = wait_till_seq_completed(hwctx, wi - CTX_MAX_CMDS);
			if (ret && ret != -EAGAIN) {
				mutex_lock(&priv->io_lock);
				return ret;
			}
			if (!ret)
				hsa_not_full = true;
		}
		/*
		 * Disconnected: wait for the ctx to reconnect. A suspend/resume or TDR
		 * recreate relinks cert_comp (the connected sentinel) after republishing
		 * the doorbell; block here transparently across it. The first command of
		 * a job (wait_through_reset) waits out the recreate so a not-yet-published
		 * submit survives a reset and runs on the fresh ctx - the queue indices
		 * are continuous across the recreate (create does not reset them; the
		 * drain advances read_index to write_index), so the already-sampled wi
		 * stays valid. Once a prefix is published (!wait_through_reset) a reset
		 * must instead unwind with -ECONNRESET: the chain cannot be split across
		 * the reset, and the SUBMITTING submitter must release pending_head so
		 * that aie4_hwctx_wait_for_running() does not block on it.
		 * aie4_hwctx_destroy() wakes job_list_wq after setting has_reset so a
		 * parked submitter re-checks. Never spins; cert_comp is published after
		 * the doorbell on create.
		 */
		ret = wait_event_freezable(priv->job_list_wq,
					   aie4_hwctx_connected(hwctx) ||
					   (!wait_through_reset &&
					    aie4_hwctx_has_reset(hwctx)));
		mutex_lock(&priv->io_lock);
		if (ret)
			return ret;
		if (!wait_through_reset && aie4_hwctx_has_reset(hwctx)) {
			XDNA_DBG(xdna, "ctx %s reset while submitting; unwinding -ECONNRESET",
				 hwctx->name);
			return -ECONNRESET;
		}
	} while (!hsa_not_full || !aie4_hwctx_connected(hwctx));
	return 0;
}

static int fill_indirect_pkt(struct amdxdna_hwctx_priv *priv, u64 slot_idx,
			     u32 total_slots, struct amdxdna_cmd_start_dpu *dpu,
			     u16 entries)
{
	struct host_queue_packet *pkt = &priv->umq_pkts[slot_idx];
	struct host_indirect_packet_entry *hipe =
		(struct host_indirect_packet_entry *)(pkt->data);
	u16 i;

	for (i = 0; i < entries; i++, dpu++, hipe++) {
		struct host_indirect_packet_data *hipd;
		u64 indirect_pkt_dev_addr;
		u32 uci = dpu->uc_index;
		u32 idx;

		/*
		 * dpu is the user-shared cmd_abo payload, so uc_index is read at
		 * use time here and indexes priv->umq_indirect_pkts[].  Reject an
		 * out-of-range value: the slot is reused, so skipping the entry
		 * would leave a stale one that count still advertises to CERT.
		 * Abort before the packet is published.
		 */
		if (uci >= HSA_MAX_LEVEL1_INDIRECT_ENTRIES) {
			XDNA_ERR(priv->hwctx->client->xdna, "Invalid uc index %d", uci);
			return -EINVAL;
		}
		idx = uci * total_slots + slot_idx;
		hipd = &priv->umq_indirect_pkts[idx];
		indirect_pkt_dev_addr = priv->umq_indirect_pkts_dev_addr +
			sizeof(struct host_indirect_packet_data) * idx;

		/* Point the indirect entry at the indirect packet. */
		hipe->host_addr_low = lower_32_bits(indirect_pkt_dev_addr);
		hipe_set_host_addr_high(&hipe->host_addr_high_uc_index,
					upper_32_bits(indirect_pkt_dev_addr));
		hipe_set_uc_index(&hipe->host_addr_high_uc_index, uci);

		/* Fill in the indirect packet. */
		hipd->payload.dpu_control_code_host_addr_low =
			lower_32_bits(dpu->instruction_buffer);
		hipd->payload.dpu_control_code_host_addr_high =
			upper_32_bits(dpu->instruction_buffer);
		hipd->payload.dtrace_buf_host_addr_low =
			lower_32_bits(dpu->dtrace_buffer);
		hipd->payload.dtrace_buf_host_addr_high =
			lower_16_bits(upper_32_bits(dpu->dtrace_buffer));
	}
	pkt->pkt_header.common_header.distribute = 1;
	pkt->pkt_header.common_header.indirect = 1;
	pkt->pkt_header.common_header.count = entries * sizeof(*hipe);
	return 0;
}

static void fill_direct_pkt(struct amdxdna_hwctx_priv *priv, u64 slot_idx,
			    struct amdxdna_cmd_start_dpu *dpu)
{
	struct host_queue_packet *pkt = &priv->umq_pkts[slot_idx];
	struct exec_buf *ebuf = (struct exec_buf *)(pkt->data);

	memset(pkt->data, 0, sizeof(pkt->data));
	ebuf->dpu_control_code_host_addr_low = lower_32_bits(dpu->instruction_buffer);
	ebuf->dpu_control_code_host_addr_high = upper_32_bits(dpu->instruction_buffer);
	ebuf->dtrace_buf_host_addr_low = lower_32_bits(dpu->dtrace_buffer);
	ebuf->dtrace_buf_host_addr_high = lower_16_bits(upper_32_bits(dpu->dtrace_buffer));
	pkt->pkt_header.common_header.distribute = 0;
	pkt->pkt_header.common_header.indirect = 0;
	pkt->pkt_header.common_header.count = sizeof(*ebuf);
}

/*
 * Build and submit one HSA command for @cmd_abo into the user host queue and
 * ring the doorbell.  Called with io_lock held.
 *
 * Security: cmd_abo is shared with user space; cache and validate its fields
 * before use and never trust the queue content (only read_index is read back).
 */
static int submit_one_cmd(struct amdxdna_hwctx *hwctx,
			  struct amdxdna_gem_obj *cmd_abo, bool last_of_chain,
			  bool first_cmd, u64 *seq)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_cmd_start_dpu *dpu;
	struct host_queue_packet *pkt;
	u32 payload_size;
	u64 slot_idx;
	u16 chained;
	int ret;
	u32 op;
	u64 ri;

	op = amdxdna_cmd_get_op(cmd_abo);
	if (op != ERT_START_DPU) {
		XDNA_ERR(xdna, "Invalid exec buf op, %d", op);
		return -EINVAL;
	}

	dpu = amdxdna_cmd_get_payload(cmd_abo, &payload_size);
	if (!dpu) {
		XDNA_ERR(xdna, "Invalid DPU payload");
		return -EINVAL;
	}
	/*
	 * cmd_abo is shared with user space; validate the cached chained count
	 * against the actual payload size before dereferencing chained+1 DPU
	 * entries, so a bogus count cannot drive an out-of-bounds read.
	 */
	chained = dpu->chained;
	if (chained >= HSA_MAX_LEVEL1_INDIRECT_ENTRIES) {
		XDNA_ERR(xdna, "Invalid DPU data");
		return -EINVAL;
	}
	if (payload_size < (u32)(chained + 1) * sizeof(*dpu)) {
		XDNA_ERR(xdna, "DPU payload %u too small for %u entries",
			 payload_size, chained + 1);
		return -EINVAL;
	}

	/*
	 * Block until a queue slot is free and the ctx is connected (io_lock is
	 * dropped across the sleeps inside and re-acquired). The only failure is a
	 * signal interrupting the wait (-ERESTARTSYS), e.g. the app being killed.
	 */
	ret = wait_till_connected_hsa_not_full(hwctx, first_cmd);
	if (ret) {
		XDNA_DBG(xdna, "Wait for queue slot / ctx reconnect interrupted, ret %d", ret);
		return ret;
	}

	slot_idx = priv->write_index & (CTX_MAX_CMDS - 1);
	if (chained) {
		ret = fill_indirect_pkt(priv, slot_idx, CTX_MAX_CMDS, dpu, chained + 1);
		if (ret)
			return ret;
	} else {
		fill_direct_pkt(priv, slot_idx, dpu);
	}

	pkt = &priv->umq_pkts[slot_idx];
	pkt->pkt_header.common_header.opcode = OPCODE_EXEC_BUF;
	pkt->pkt_header.common_header.chain_flag =
		last_of_chain ? CHAIN_FLG_LAST_CMD : CHAIN_FLG_NOT_LAST_CMD;
	pkt->pkt_header.common_header.reserved = 0x0;
	pkt->pkt_header.completion_signal = amdxdna_gem_dev_addr(cmd_abo) +
					    offsetof(struct amdxdna_cmd, header);
	ri = get_read_index(hwctx);
	*seq = publish_cmd(hwctx);
	aie4_doorbell_ring(hwctx);
	trace_xdna_job_queue(hwctx->name, *seq, *seq + 1 - ri, "job submitted");
	XDNA_DBG(xdna, "Submitted one cmd, %s seq %lld", hwctx->name, *seq);
	return 0;
}

/*
 * Return the head running job without removing it.  The job worker keeps the
 * in-flight job on the list while it waits so that a disconnect (suspend) can
 * just leave it there for resume - no dequeue/requeue - and running_job_list is
 * never transiently empty while a job is in flight.
 */
static struct amdxdna_sched_job *peek_running_job(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_sched_job *job;

	mutex_lock(&priv->io_lock);
	job = list_first_entry_or_null(&priv->running_job_list,
				       struct amdxdna_sched_job, aie4_job_list);
	mutex_unlock(&priv->io_lock);
	return job;
}

/* Remove a job from the running list once it is completed or reaped. */
static void dequeue_running_job(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;

	mutex_lock(&priv->io_lock);
	list_del(&job->aie4_job_list);
	mutex_unlock(&priv->io_lock);
}

static void aie4_job_release(struct kref *ref)
{
	struct amdxdna_sched_job *job =
		container_of(ref, struct amdxdna_sched_job, refcnt);

	amdxdna_job_cleanup(job);
	kfree(job);
}

static void job_done(struct amdxdna_sched_job *job)
{
	amdxdna_io_stats_job_done(job->hwctx->client);
	job->aie4_job_state = AIE4_JOB_STATE_DONE;
	/*
	 * Release the address-space reference taken at submit.  On SVA/IOMMU
	 * platforms the device walks the submitter's page tables while the job
	 * runs, so its mm must stay alive until completion.
	 */
	mmput_async(job->mm);
	kref_put(&job->refcnt, aie4_job_release);
}

static void job_complete(struct amdxdna_sched_job *job)
{
	job_done(job);
}

/*
 * When CERT cannot complete a command (context teardown), the driver advances
 * read_index so any waiter observes the command as finished.  Only valid while
 * the context is disconnected -- never race CERT's own read_index updates.
 */
static void update_read_index(struct amdxdna_hwctx *hwctx, u64 idx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;

	/* Order cmd-bo state write before the waiter observes completion. */
	wmb();
	WRITE_ONCE(*priv->umq_read_index, idx);
}

static void job_abort(struct amdxdna_sched_job *job)
{
	struct amdxdna_hwctx *hwctx = job->hwctx;

	XDNA_WARN(hwctx->client->xdna, "aborting %s job %lld", hwctx->name, job->seq);
	amdxdna_cmd_set_state(job->cmd_bo, ERT_CMD_STATE_ABORT);
	/*
	 * Only force read_index forward when CERT has not already moved it past this
	 * job. On the reset drain read_index is still <= job->seq (CERT stopped), so
	 * advance it here to release waiters. For a partial chain closed by a later
	 * command's LAST_CMD, CERT has already advanced read_index past this job -
	 * do not clobber it.
	 */
	if (get_read_index(hwctx) <= job->seq)
		update_read_index(hwctx, job->seq + 1);
	job_done(job);
}

/*
 * For a timed-out command chain, identify the failing sub-command from the
 * cached health report's runlist index, record it in the chain's error_index,
 * and fill that sub-command's data region with the health report. The runlist
 * index and the report body are read under a single io_lock hold so they cannot
 * be taken from two different cached reports.
 */
static void aie4_fill_chain_health_data(struct amdxdna_hwctx *hwctx,
					struct amdxdna_gem_obj *cmd_abo)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_cmd_chain *payload;
	struct amdxdna_gem_obj *sub_abo;
	u32 payload_len, ccnt, i = 0;

	payload = amdxdna_cmd_get_payload(cmd_abo, &payload_len);
	if (!payload) {
		XDNA_ERR(xdna, "No chain payload for timed-out command");
		return;
	}
	ccnt = payload->command_count;
	if (!ccnt || payload_len < struct_size(payload, data, ccnt))
		return;

	mutex_lock(&priv->io_lock);
	if (priv->cached_ctx_error_valid)
		i = priv->cached_ctx_error.app_health_report.runlist_read_idx;
	if (i >= ccnt)
		i = 0;
	payload->error_index = i;
	sub_abo = amdxdna_gem_get_obj(hwctx->client, (u32)payload->data[i], AMDXDNA_BO_SHARE);
	if (sub_abo)
		aie4_fill_health_data_locked(sub_abo, hwctx);
	mutex_unlock(&priv->io_lock);

	if (sub_abo)
		amdxdna_gem_put_obj(sub_abo);
	else
		XDNA_ERR(xdna, "Failed to find sub cmd BO %u", (u32)payload->data[i]);
}

/*
 * Complete an in-flight job that could not finish because the context hit a
 * critical firmware error and is being reset. Attach the cached health report
 * (into the failing sub-command for a chain), mark the command TIMEOUT, advance
 * read_index so waiters observe completion, and signal the fence. Runs with the
 * context DISCONNECTED (firmware quiesced by aie4_hwctx_destroy).
 */
static void job_timeout(struct amdxdna_sched_job *job)
{
	struct amdxdna_hwctx *hwctx = job->hwctx;

	XDNA_ERR(hwctx->client->xdna, "timing out %s job %lld", hwctx->name, job->seq);

	if (amdxdna_cmd_get_op(job->cmd_bo) == ERT_CMD_CHAIN)
		aie4_fill_chain_health_data(hwctx, job->cmd_bo);
	else
		aie4_fill_health_data(job->cmd_bo, hwctx);

	amdxdna_cmd_set_state(job->cmd_bo, ERT_CMD_STATE_TIMEOUT);
	update_read_index(hwctx, job->seq + 1);
	job_done(job);
}

static void job_worker(struct work_struct *work)
{
	struct amdxdna_hwctx_priv *priv =
		container_of(work, struct amdxdna_hwctx_priv, job_work);
	struct amdxdna_hwctx *hwctx = priv->hwctx;
	struct amdxdna_sched_job *job;

	while ((job = peek_running_job(hwctx))) {
		wait_till_seq_completed(hwctx, job->seq);
		if (get_read_index(hwctx) > job->seq) {
			trace_xdna_job_queue(hwctx->name, job->seq,
					     READ_ONCE(hwctx->priv->write_index) -
					     get_read_index(hwctx), "job complete");
			dequeue_running_job(hwctx, job);
			/*
			 * read_index advanced past this job. A fully published
			 * job (SUBMITTED) ran to completion. A partial chain
			 * (SUBMITTING: a later sub-command failed to publish, so
			 * the chain never got CHAIN_FLG_LAST_CMD) only reaches
			 * here once a *later* command's LAST_CMD closes the
			 * dangling runlist and advances read_index past it - so
			 * report it ABORT, not a false completion. If no such
			 * command follows, read_index never advances and we stay
			 * parked in wait_till_seq_completed() above until the
			 * user's wait_command() times out and breaks the wait
			 * (or ctx teardown reaps it).
			 */
			if (job->aie4_job_state != AIE4_JOB_STATE_SUBMITTED)
				job_abort(job);
			else
				job_complete(job);
		} else if (aie4_hwctx_has_reset(hwctx)) {
			bool faulted;

			dequeue_running_job(hwctx, job);
			/*
			 * A cached ctx-error report means a genuine fault: the
			 * oldest undrained job is the one that faulted, so report it
			 * TIMEOUT with the report attached and consume the report.
			 * Every job after that - and any benign teardown that set
			 * has_reset without a fault (suspend-clean/FLR/fini) - is
			 * ABORTed. cached_ctx_error_valid is per-ctx and cleared here
			 * or in aie4_hwctx_create(), so a job drained by a later
			 * worker invocation of the same reset - e.g. a partial chain
			 * re-queued after the faulting head was timed out - is
			 * ABORTed, not reported TIMEOUT a second time.
			 */
			mutex_lock(&priv->io_lock);
			faulted = priv->cached_ctx_error_valid;
			mutex_unlock(&priv->io_lock);
			if (faulted) {
				job_timeout(job);
				mutex_lock(&priv->io_lock);
				priv->cached_ctx_error_valid = false;
				mutex_unlock(&priv->io_lock);
			} else {
				job_abort(job);
			}
		} else {
			/* suspend/resume */
			break;
		}
	}
}

void aie4_hwctx_wait_for_running(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_sched_job *job;

	if (!priv->kernel_submit)
		return;

	/*
	 * An in-flight submitter parks the head job at AIE4_JOB_STATE_SUBMITTING
	 * while it publishes (holding io_lock across sleeps) and advances
	 * pending_head when it completes or unwinds, waking job_list_wq. Wait for
	 * it so we do not tear down under an active publisher.
	 */
	mutex_lock(&priv->io_lock);
	job = READ_ONCE(priv->pending_head);
	if (job && job->aie4_job_state == AIE4_JOB_STATE_SUBMITTING) {
		mutex_unlock(&priv->io_lock);
		wait_event(priv->job_list_wq,
			   READ_ONCE(priv->pending_head) != job);
	} else {
		mutex_unlock(&priv->io_lock);
	}

	/*
	 * Wait for the worker to finish draining the running list. On a reset
	 * (has_reset set by aie4_hwctx_destroy, which does NOT cancel the worker)
	 * the worker times out the faulting head job and aborts the rest. Any
	 * unwound submitter has already put its job on the running list before
	 * advancing pending_head above (waited on in Part 1), and no new submitter
	 * can publish under has_reset, so one worker pass drains everything left.
	 * Kick it and flush_work() so we wait for that pass to *finish* - not merely
	 * for the list to look empty, which a peeked wait condition would observe
	 * after dequeue but before the last job's timeout/abort completes, letting
	 * teardown race the worker.
	 */
	queue_work(priv->job_work_q, &priv->job_work);
	flush_work(&priv->job_work);
}

/*
 * Resume kernel-mode submission after the ctx was recreated (S3/S4 resume).  Any
 * jobs the worker preserved on suspend are still queued on running_job_list, and
 * the HSA queue (a host-resident BO) kept its packets and write/read indices
 * across suspend.  Ring the doorbell so the fresh firmware ctx re-consumes the
 * un-drained packets, then restart the worker to reap them as they complete.
 */
void aie4_hwctx_resume_jobs(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;

	if (!priv->kernel_submit)
		return;

	mutex_lock(&priv->io_lock);
	if (list_empty(&priv->running_job_list)) {
		mutex_unlock(&priv->io_lock);
		return;
	}
	aie4_doorbell_ring(hwctx);
	mutex_unlock(&priv->io_lock);

	queue_work(priv->job_work_q, &priv->job_work);
}

/*
 * Submit the command(s) carried by @job into the host queue.  Called with
 * io_lock held.  A single ERT_START_DPU maps to one queue entry; an
 * ERT_CMD_CHAIN expands to one entry per sub-command, only the last of which
 * carries CHAIN_FLG_LAST_CMD so CERT runs the whole chain back to back.
 *
 * job->seq tracks the last published sequence; the worker waits on it to reap
 * the entire chain.  job->aie4_job_state advances past PENDING as soon as any
 * sub-command is published, so the caller knows whether in-flight commands must
 * still be reaped even when a later sub-command fails to enqueue.
 *
 * Security: the chain payload and its BO handles come from user space; cache
 * command_count and validate it against the payload size before walking the
 * handle array so a bogus count cannot drive an out-of-bounds read.
 */
static int submit_job_cmds(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job)
{
	struct amdxdna_gem_obj *cmd_abo = job->cmd_bo;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_cmd_chain *payload;
	u32 op = amdxdna_cmd_get_op(cmd_abo);
	u32 payload_len, ccnt;
	int ret;
	u32 i;

	/* Single cmd. */
	if (op == ERT_START_DPU) {
		ret = submit_one_cmd(hwctx, cmd_abo, true, true, &job->seq);
		if (!ret)
			job->aie4_job_state = AIE4_JOB_STATE_SUBMITTED;
		return ret;
	}

	/* Cmd chain. */
	payload = amdxdna_cmd_get_payload(cmd_abo, &payload_len);
	if (!payload) {
		XDNA_ERR(xdna, "Invalid cmd payload for chained cmd");
		return -EINVAL;
	}
	ccnt = payload->command_count;
	/*
	 * A chain (runlist) must fit within the queue. CERT advances the host-visible
	 * read_index only once per runlist - at the last sub-command (CHAIN_FLG_LAST_CMD),
	 * not per sub-command - so a chain's own entries never free a queue slot until
	 * the whole chain has been published and run. A chain longer than the queue
	 * could therefore never publish its tail: it would block forever in
	 * wait_till_connected_hsa_not_full() waiting for a slot that only frees at chain end.
	 * Reject ccnt > CTX_MAX_CMDS. Also validate against the payload size before
	 * walking the handle array so a bogus count cannot drive an out-of-bounds read.
	 */
	if (!ccnt || ccnt > CTX_MAX_CMDS ||
	    payload_len < struct_size(payload, data, ccnt)) {
		XDNA_ERR(xdna, "Invalid command count %u", ccnt);
		return -EINVAL;
	}

	for (i = 0; i < ccnt; i++) {
		u32 boh = (u32)(payload->data[i]);
		struct amdxdna_gem_obj *abo;

		abo = amdxdna_gem_get_obj(hwctx->client, boh, AMDXDNA_BO_SHARE);
		if (!abo) {
			XDNA_ERR(xdna, "Failed to find cmd BO %u", boh);
			ret = -ENOENT;
			break;
		}
		/*
		 * submit_one_cmd() blocks in wait_till_connected_hsa_not_full() until the
		 * ctx is connected and a slot is free, so a concurrent suspend/disconnect
		 * is waited out inline rather than returned here. The first sub-command
		 * (i == 0, nothing published yet) waits through a TDR reset and runs on
		 * the recreated ctx; a later sub-command returns -ECONNRESET if a reset
		 * landed while waiting for a slot, so the published prefix is not split
		 * across the reset. It also returns -ERESTARTSYS on a signal, or a
		 * validation error. Break on any; a published prefix is then reaped by
		 * the job worker's reset drain (see below).
		 */
		ret = submit_one_cmd(hwctx, abo, i + 1 == ccnt, i == 0, &job->seq);
		amdxdna_gem_put_obj(abo);
		if (ret)
			break;
		job->aie4_job_state = AIE4_JOB_STATE_SUBMITTING;
	}
	if (i == ccnt)
		job->aie4_job_state = AIE4_JOB_STATE_SUBMITTED;

	/*
	 * As long as at least one sub-command was published, return success so the
	 * caller enqueues the job on the running list; the job worker then reaps the
	 * published prefix and reports the partial chain as failed (ABORT). Only when
	 * nothing was published (i == 0) is the error returned to the caller.
	 */
	if (i > 0)
		return 0;

	return ret;
}

/*
 * Whole-job submission is serialized across submitters that share a ctx via the
 * pending list: a job is appended on entry and only the head of the list is
 * allowed to publish its command(s).  Because the head stays on the list for the
 * entire duration of submit_job_cmds() -- which may drop io_lock to wait for
 * free queue slots -- no other submitter can interleave its commands into the
 * middle of the head job's command chain.  io_lock protects the lists; the
 * job_list_wq waitqueue notifies parked submitters when the head changes.
 */
/* Publish the current pending-list head for the lockless submit wait condition.
 * Caller holds io_lock.
 */
static void update_pending_head(struct amdxdna_hwctx_priv *priv)
{
	WRITE_ONCE(priv->pending_head,
		   list_first_entry_or_null(&priv->pending_job_list,
					    struct amdxdna_sched_job, aie4_job_list));
}

static void enqueue_pending_job(struct amdxdna_hwctx *hwctx,
				struct amdxdna_sched_job *job)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;

	mutex_lock(&priv->io_lock);
	list_add_tail(&job->aie4_job_list, &priv->pending_job_list);
	job->aie4_job_state = AIE4_JOB_STATE_PENDING;
	update_pending_head(priv);
	mutex_unlock(&priv->io_lock);
}

static void cancel_pending_job(struct amdxdna_hwctx *hwctx,
			       struct amdxdna_sched_job *job)
{
	struct amdxdna_hwctx_priv *priv = hwctx->priv;

	mutex_lock(&priv->io_lock);
	list_del(&job->aie4_job_list);
	job->aie4_job_state = AIE4_JOB_STATE_INIT;
	update_pending_head(priv);
	mutex_unlock(&priv->io_lock);
	/* Let the next pending submitter re-check whether it is now first. */
	wake_up_all(&priv->job_list_wq);
}

int aie4_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_hwctx_priv *priv = hwctx->priv;
	struct amdxdna_dev *xdna = client->xdna;
	u32 op;
	int ret;

	XDNA_DBG(xdna, "ctx %s job 0x%llx received", hwctx->name, (u64)job);

	if (!priv->kernel_submit) {
		/* User-mode submission rings its own doorbell; no kernel submit. */
		XDNA_ERR(xdna, "cmd submit ioctl not supported in user-mode submission");
		return -EOPNOTSUPP;
	}

	if (!job->cmd_bo) {
		XDNA_ERR(xdna, "No command BO in job");
		return -EINVAL;
	}

	op = amdxdna_cmd_get_op(job->cmd_bo);
	if (op != ERT_START_DPU && op != ERT_CMD_CHAIN) {
		XDNA_ERR(xdna, "Invalid cmd opcode %d", op);
		return -EINVAL;
	}

	INIT_LIST_HEAD(&job->aie4_job_list);

	/*
	 * Hold a reference on the submitter's address space until the job
	 * completes (job_done): on SVA/IOMMU platforms the device walks the
	 * submitter's page tables while the command runs.  Balanced with the
	 * mmput_async() in job_done() and the mmput() on the failure paths below.
	 */
	if (!mmget_not_zero(job->mm)) {
		XDNA_ERR(xdna, "Failed to get mm reference");
		return -ESRCH;
	}

	down_read(&xdna->notifier_lock);
	while (!list_empty(&client->bo_invalid_list)) {
		up_read(&xdna->notifier_lock);
		ret = amdxdna_client_populate_ranges(client);
		if (ret) {
			XDNA_ERR(xdna, "Populate ranges failed, ret %d", ret);
			goto put_mm;
		}
		down_read(&xdna->notifier_lock);
	}
	atomic64_inc(&hwctx->job_submit_cnt);
	up_read(&xdna->notifier_lock);

	/*
	 * Wait until this job is at the head of the pending list before touching
	 * the queue (see enqueue_pending_job).  Freezable so the freezer can
	 * suspend a parked submitter in place across S3/S4 rather than aborting
	 * the suspend; still interruptible so a signal (app exit/kill/^C) unwinds
	 * it and does not keep ctx teardown (synchronize_srcu) blocked.  No
	 * disconnect check is needed here: submit_one_cmd() waits on the connected
	 * sentinel in wait_till_connected_hsa_not_full(), so a submit onto a
	 * torn-down ctx blocks until reconnect instead of publishing onto a dead
	 * doorbell (a published-prefix chain then unwinds with -ECONNRESET; a signal
	 * unwinds it meanwhile).
	 */
	enqueue_pending_job(hwctx, job);
	ret = wait_event_freezable(priv->job_list_wq,
				   READ_ONCE(priv->pending_head) == job);
	if (ret)
		goto put_mm_dec;

	mutex_lock(&priv->io_lock);
	ret = submit_job_cmds(hwctx, job);
	if (ret) {
		mutex_unlock(&priv->io_lock);
		goto put_mm_dec;
	}

	list_move_tail(&job->aie4_job_list, &priv->running_job_list);
	update_pending_head(priv);
	*seq = job->seq;
	mutex_unlock(&priv->io_lock);

	amdxdna_io_stats_job_start(client);
	/* Release the next pending submitter and kick the reaper. */
	wake_up_all(&priv->job_list_wq);
	queue_work(priv->job_work_q, &priv->job_work);
	return 0;

put_mm_dec:
	cancel_pending_job(hwctx, job);
	atomic64_dec(&hwctx->job_submit_cnt);
	wake_up(&hwctx->job_free_wq);
put_mm:
	mmput(job->mm);
	return ret;
}

static int aie4_hwctx_cfg_debug_bo(struct amdxdna_hwctx *hwctx, u32 meta_bo_hdl,
				   bool attach)
{
	struct aie4_msg_context_config_cert_logging cl = { };
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_fw_buffer_metadata *meta;
	struct amdxdna_gem_obj *meta_bo;
	struct amdxdna_gem_obj *log_bo;
	u32 prev_size = 0;
	u64 base_addr;
	u32 property;
	u32 num_ucs;
	u32 index;
	int ret;
	int i;

	meta_bo = amdxdna_gem_get_obj(client, meta_bo_hdl, AMDXDNA_BO_SHARE);
	if (!meta_bo) {
		XDNA_ERR(xdna, "Get meta bo %u failed", meta_bo_hdl);
		return -EINVAL;
	}

	if (meta_bo->mem.size < sizeof(*meta)) {
		XDNA_ERR(xdna, "meta bo size %lu is too small", meta_bo->mem.size);
		ret = -EINVAL;
		goto put_meta_bo;
	}

	meta = amdxdna_gem_vmap(meta_bo);
	if (!meta) {
		ret = -ENOMEM;
		goto put_meta_bo;
	}

	/*
	 * meta lives in a user-shared BO that a second user thread can mutate
	 * concurrently.  Snapshot num_ucs once so the bound check, struct_size()
	 * check, loop bound, and value sent to firmware all agree; otherwise a
	 * racing writer could pass the checks with a small value and drive the
	 * loop past the vmapped BO with a large one (out-of-bounds read).
	 */
	num_ucs = READ_ONCE(meta->num_ucs);

	switch (meta->buf_type) {
	case AMDXDNA_FW_BUF_LOG:
		property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_LOG_BUFFER;
		break;
	case AMDXDNA_FW_BUF_DEBUG:
		property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_DEBUG_BUFFER;
		break;
	case AMDXDNA_FW_BUF_TRACE:
		property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_TRACE_BUFFER;
		break;
	case AMDXDNA_FW_BUF_DBG_Q:
		property = AIE4_CONFIGURE_HW_CONTEXT_PROPERTY_CERT_DEBUG_QUEUE;
		break;
	default:
		XDNA_ERR(xdna, "Unsupported buf_type %u", meta->buf_type);
		ret = -EOPNOTSUPP;
		goto put_meta_bo;
	}

	if (num_ucs > AIE4_MAX_NUM_CERTS) {
		XDNA_ERR(xdna, "num_ucs %u exceeds %d", num_ucs, AIE4_MAX_NUM_CERTS);
		ret = -EINVAL;
		goto put_meta_bo;
	}

	if (meta_bo->mem.size < struct_size(meta, uc_info, num_ucs)) {
		XDNA_ERR(xdna, "meta bo size %lu too small for %u ucs",
			 meta_bo->mem.size, num_ucs);
		ret = -EINVAL;
		goto put_meta_bo;
	}

	log_bo = amdxdna_gem_get_obj(client, meta->bo_handle, AMDXDNA_BO_SHARE);
	if (!log_bo) {
		XDNA_ERR(xdna, "Get payload bo %u failed", meta->bo_handle);
		ret = -EINVAL;
		goto put_meta_bo;
	}

	base_addr = amdxdna_gem_dev_addr(log_bo);

	for (i = 0; i < num_ucs; i++) {
		u32 slice_size = meta->uc_info[i].size;
		u32 next_size;

		index = meta->uc_info[i].index;
		if (index >= AIE4_MAX_NUM_CERTS) {
			XDNA_ERR(xdna, "Invalid uc index %u", index);
			ret = -EINVAL;
			goto put_log_bo;
		}

		if (!attach) {
			cl.info[index].paddr = 0;
			cl.info[index].size = 0;
			continue;
		}

		if (!slice_size)
			continue;

		if (cl.info[index].size) {
			XDNA_ERR(xdna, "Duplicate uc index %u", index);
			ret = -EINVAL;
			goto put_log_bo;
		}

		if (check_add_overflow(prev_size, slice_size, &next_size) ||
		    next_size > log_bo->mem.size) {
			XDNA_ERR(xdna,
				 "uc[%u] slice 0x%x at 0x%x overflows payload bo size %lu",
				 index, slice_size, prev_size, log_bo->mem.size);
			ret = -EINVAL;
			goto put_log_bo;
		}

		cl.info[index].paddr = base_addr + prev_size;
		cl.info[index].size = slice_size;
		prev_size = next_size;
	}

	cl.num = FIELD_PREP(AIE4_MSG_CERT_LOG_NUM, attach ? num_ucs : 0);

	ret = aie4_configure_hw_context_cert_log(ndev, hwctx->priv->hw_ctx_id,
						 property, &cl);
	XDNA_DBG(xdna, "%s CERT bo %u on %s, property %u, ret %d",
		 attach ? "attach" : "detach", meta_bo_hdl,
		 hwctx->name, property, ret);

put_log_bo:
	amdxdna_gem_put_obj(log_bo);
put_meta_bo:
	amdxdna_gem_put_obj(meta_bo);
	return ret;
}

int aie4_hwctx_config(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	switch (type) {
	case DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF:
		return aie4_hwctx_cfg_debug_bo(hwctx, (u32)value, true);
	case DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF:
		return aie4_hwctx_cfg_debug_bo(hwctx, (u32)value, false);
	default:
		XDNA_DBG(xdna, "Not supported type %d", type);
		return -EOPNOTSUPP;
	}
}
