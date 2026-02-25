// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */
#include <drm/drm_cache.h>
#include <linux/dma-mapping.h>
#include <linux/dma-buf.h>

#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_res_solver.h"

int enable_polling;
module_param(enable_polling, int, 0644);
MODULE_PARM_DESC(enable_polling, "Enable polling mode. Polling mode disabled by default.");

int verbosity;
module_param(verbosity, int, 0644);
MODULE_PARM_DESC(verbosity, "[Debug] Enabling verbosity. default is 0");

int partition_size = 4;
module_param(partition_size, int, 0644);
MODULE_PARM_DESC(partition_size, "Test only option: default partition size");

unsigned int ve2_hwctx_limit;
module_param(ve2_hwctx_limit, uint, 0400);
MODULE_PARM_DESC(ve2_hwctx_limit, "[Debug] Maximum number of hwctx. 0 = Use default");

int start_col;
module_param(start_col, int, 0644);
MODULE_PARM_DESC(start_col, "Test only option: lead column set to start_col");

int max_col;
module_param(max_col, int, 0644);
MODULE_PARM_DESC(max_col, "Max column supported by this driver");

#define CTX_TIMER	(nsecs_to_jiffies(1))

/*
 * struct ve2_dpu_data - interpretation of data payload for ERT_START_DPU
 *
 * @instruction_buffer:       address of instruction buffer
 * @instruction_buffer_size:  size of instruction buffer in bytes
 * @uc_index:                 microblaze controller index
 * @chained:                  number of following ve2_dpu_data elements
 *
 * The data payload for ERT_START_DPU is interpreted as fixed instruction
 * buffer address along with instruction count, followed by regular kernel
 * arguments.
 */
struct ve2_dpu_data {
	u64 dtrace_buffer;		/* dtrace buffer address 2 words */
	u64 instruction_buffer;		/* buffer address 2 words */
	u32 instruction_buffer_size;	/* size of buffer in bytes */
	u16 uc_index;			/* microblaze controller index */
	u16 chained;			/* number of following ve2_dpu_data elements */
};

static inline struct ve2_dpu_data *get_ve2_dpu_data_next(struct ve2_dpu_data *dpu_data)
{
	if (dpu_data->chained == 0)
		return NULL;

	return dpu_data + 1;
}

/*
 * ve2_check_slot_available - Check if a queue slot is available
 * @hwctx: Hardware context
 *
 * Returns true if at least one slot is available, false otherwise.
 * This is used as the condition for wait_event_interruptible_timeout.
 *
 */
static bool ve2_check_slot_available(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_ctx_priv *priv = hwctx->priv;
	struct ve2_hsa_queue *queue = &priv->hwctx_hsa_queue;
	struct host_queue_header *header = &queue->hsa_queue_p->hq_header;
	u32 capacity = header->capacity;
	u64 outstanding;
	bool available;
	u32 slot_idx;

	mutex_lock(&queue->hq_lock);
	/* Sync read_index before reading (device may have written) */
	hsa_queue_sync_read_index_for_read(queue);
	outstanding = queue->reserved_write_index - header->read_index;
	if (outstanding >= capacity) {
		mutex_unlock(&queue->hq_lock);
		return false;
	}

	/*
	 * Also check that the next slot to be reserved is actually available.
	 * The slot is available when the pending entry is NULL: cleared by
	 * ve2_hwctx_job_release_locked() after the waiter releases the job,
	 * or zero-initialized for slots not yet used.
	 */
	slot_idx = queue->reserved_write_index % capacity;
	mutex_lock(&priv->privctx_lock);
	available = !priv->pending[slot_idx];
	mutex_unlock(&priv->privctx_lock);
	mutex_unlock(&queue->hq_lock);

	return available;
}

/*
 * ve2_wait_for_retry_slot - Wait for a queue slot to become available
 * @hwctx: Hardware context
 * @timeout_ms: Maximum time to wait in milliseconds
 *
 * This function uses wait_event_interruptible_timeout to sleep until
 * a slot becomes available. The IRQ handler will wake us up when
 * commands complete and slots are freed.
 *
 * Returns:
 *   0 on success (slot available)
 *   -ETIMEDOUT if timeout expired
 *   negative error code if interrupted
 */
static int ve2_wait_for_retry_slot(struct amdxdna_ctx *hwctx, u32 timeout_ms)
{
	struct amdxdna_ctx_priv *priv = hwctx->priv;
	unsigned long timeout_jiffies = msecs_to_jiffies(timeout_ms);
	int ret;

	ret = wait_event_interruptible_timeout(priv->waitq,
					       ve2_check_slot_available(hwctx),
					       timeout_jiffies);

	if (ret == 0)
		return -ETIMEDOUT;
	if (ret < 0)
		return ret;  /* Interrupted */

	return 0;
}

static struct host_queue_packet *
hsa_queue_reserve_slot(struct amdxdna_dev *xdna, struct amdxdna_ctx_priv *priv, u64 *slot)
{
	struct ve2_hsa_queue *queue = &priv->hwctx_hsa_queue;
	struct host_queue_header *header = &queue->hsa_queue_p->hq_header;
	u32 capacity = header->capacity;
	u32 slot_idx;
	u64 outstanding;

	mutex_lock(&queue->hq_lock);

	/*
	 * Check against reserved_write_index to account for in-flight reservations.
	 */
	/* Sync read_index before reading (device may have written) */
	hsa_queue_sync_read_index_for_read(queue);
	if (queue->reserved_write_index < header->read_index) {
		XDNA_ERR(xdna, "HSA Queue: reserved_write_index(%llu) < read_index(%llu)",
			 queue->reserved_write_index, header->read_index);
		mutex_unlock(&queue->hq_lock);
		return NULL;
	}

	outstanding = queue->reserved_write_index - header->read_index;
	if (outstanding >= capacity) {
		/* Use DBG level - expected during high queue utilization */
		XDNA_DBG(xdna, "HSA Queue full: outstanding=%llu >= capacity=%u",
			 outstanding, capacity);
		mutex_unlock(&queue->hq_lock);
		return ERR_PTR(-EBUSY);
	}

	/*
	 * Runlist optimization: Slot availability is determined by read_index only.
	 * Host uses read_index; no INVALID state check. Ring buffer math ensures
	 * we never overwrite when outstanding < capacity.
	 *
	 * Additionally, we must ensure the pending slot is free before reusing.
	 * Pending is cleared in ve2_cmd_wait when the waiting thread runs, which
	 * can lag behind read_index advance. Without this check, multi-threaded
	 * submit can hit "No more room" in ve2_hwctx_add_job.
	 */
	slot_idx = queue->reserved_write_index % capacity;
	mutex_lock(&priv->privctx_lock);
	if (priv->pending[slot_idx]) {
		mutex_unlock(&priv->privctx_lock);
		mutex_unlock(&queue->hq_lock);
		return ERR_PTR(-EBUSY);
	}
	mutex_unlock(&priv->privctx_lock);

	/* Reserve this slot by incrementing reserved_write_index. */
	*slot = queue->reserved_write_index++;
	queue->hq_complete.hqc_mem[slot_idx] = ERT_CMD_STATE_NEW;
	/* Sync completion memory after writing (device will read) */
	hsa_queue_sync_completion_for_write(queue, slot_idx);

	mutex_unlock(&queue->hq_lock);

	/* Return packet pointer. Caller can now prepare packet in parallel. */
	return &queue->hsa_queue_p->hq_entry[slot_idx];
}

/* Commit the prepared packet by updating write_index when all prior slots are ready.
 * This ensures CERT sees packets in order even if prepared out-of-order.
 */
static void hsa_queue_commit_slot(struct amdxdna_dev *xdna, struct amdxdna_ctx_priv *priv,
				  u64 slot)
{
	struct ve2_hsa_queue *queue = &priv->hwctx_hsa_queue;
	struct host_queue_header *header = &queue->hsa_queue_p->hq_header;
	u32 capacity = header->capacity;
	u32 slot_idx = slot % capacity;
	struct host_queue_packet *pkt = &queue->hsa_queue_p->hq_entry[slot_idx];

	mutex_lock(&queue->hq_lock);
	/* Set packet type to valid so CERT can process it */
	pkt->xrt_header.common_header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
	/* Sync packet after writing (device will read) */
	hsa_queue_sync_packet_for_write(queue, slot_idx);

	/* Mark this slot as ready in driver tracking */
	queue->hq_complete.hqc_mem[slot_idx] = ERT_CMD_STATE_SUBMITTED;
	/* Sync completion memory after writing (device will read) */
	hsa_queue_sync_completion_for_write(queue, slot_idx);

	/* Advance write_index as far as possible through all ready slots. */
	while (header->write_index < queue->reserved_write_index) {
		u32 next_idx = header->write_index % capacity;
		/* Sync completion memory before reading (device may have written) */
		hsa_queue_sync_completion_for_read(queue, next_idx);
		enum ert_cmd_state state = queue->hq_complete.hqc_mem[next_idx];

		if (state != ERT_CMD_STATE_SUBMITTED)
			break;

		header->write_index++;
	}
	/* Sync write_index after writing (device will read) */
	hsa_queue_sync_write_index_for_write(queue);

	mutex_unlock(&queue->hq_lock);
}

static void ve2_job_release(struct kref *ref)
{
	struct amdxdna_sched_job *job;

	job = container_of(ref, struct amdxdna_sched_job, refcnt);
	amdxdna_sched_job_cleanup(job);
}

static void ve2_job_put(struct amdxdna_sched_job *job)
{
	kref_put(&job->refcnt, ve2_job_release);
}

/**
 * ve2_hwctx_add_job - Add a job to the hardware context's pending list.
 * @hwctx: Pointer to the hardware context.
 * @job: Pointer to the job to be added.
 * @seq: Sequence number associated with the job.
 * @cmd_cnt: Number of commands submitted with this job.
 *
 * Returns 0 on success, or a negative error code if the job cannot be added.
 */
static inline int ve2_hwctx_add_job(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job,
				    u64 seq, u32 cmd_cnt)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_ctx_priv *priv = hwctx->priv;
	int idx;

	mutex_lock(&priv->privctx_lock);
	hwctx->submitted += cmd_cnt;
	job->seq = seq;

	idx = get_job_idx(job->seq);
	if (priv->pending[idx]) {
		XDNA_ERR(xdna, "No more room for new command!!!");
		mutex_unlock(&priv->privctx_lock);
		return -EINVAL;
	}

	priv->pending[idx] = job;
	priv->state = AMDXDNA_HWCTX_STATE_ACTIVE;
	mutex_unlock(&priv->privctx_lock);

	XDNA_DBG(xdna, "hwctx %p job added: seq=%llu, idx=%d, cmd_cnt=%u, total_submitted=%llu",
		 hwctx, seq, idx, cmd_cnt, hwctx->submitted);

	return 0;
}

static inline struct amdxdna_sched_job *ve2_hwctx_get_job(struct amdxdna_ctx *hwctx, u64 seq)
{
	return hwctx->priv->pending[get_job_idx(seq)];
}

/*
 * ve2_hwctx_job_release_locked - Release a job with hq_lock already held
 * @hwctx: Hardware context
 * @job: Job to release
 *
 * Caller MUST hold hq_lock. This function will acquire privctx_lock internally.
 */
static inline void ve2_hwctx_job_release_locked(struct amdxdna_ctx *hwctx,
						struct amdxdna_sched_job *job)
{
	struct amdxdna_ctx_priv *priv_ctx = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	struct amdxdna_cmd_chain *cmd_chain;
	u32 cmd_cnt = 1;
	u32 op;

	op = amdxdna_cmd_get_op(cmd_bo);
	if (op == ERT_CMD_CHAIN) {
		cmd_chain = amdxdna_cmd_get_payload(cmd_bo, NULL);
		cmd_cnt = cmd_chain->command_count;
	}
	hwctx->completed += cmd_cnt;

	XDNA_DBG(xdna, "hwctx %p job release: seq=%llu, cmd_cnt=%u, completed=%llu",
		 hwctx, job->seq, cmd_cnt, hwctx->completed);
	if (hwctx->completed == hwctx->submitted)
		priv_ctx->state = AMDXDNA_HWCTX_STATE_IDLE;

	/* Caller already holds hq_lock, just acquire privctx_lock */
	mutex_lock(&priv_ctx->privctx_lock);

	/*
	 * Runlist optimization: Slot reuse is determined by read_index only.
	 * Host does not write INVALID to mark slots free; CERT advances read_index
	 * when done. No need to clear hqc_mem here.
	 */
	// Reset the pending list
	priv_ctx->pending[get_job_idx(job->seq)] = NULL;
	ve2_job_put(job);
	mutex_unlock(&priv_ctx->privctx_lock);
}

/*
 * ve2_hwctx_job_release - Release a job (acquires hq_lock)
 * @hwctx: Hardware context
 * @job: Job to release
 *
 * Caller must NOT hold hq_lock. Use ve2_hwctx_job_release_locked() if already holding.
 */
static inline void ve2_hwctx_job_release(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job)
{
	mutex_lock(&hwctx->priv->hwctx_hsa_queue.hq_lock);
	ve2_hwctx_job_release_locked(hwctx, job);
	mutex_unlock(&hwctx->priv->hwctx_hsa_queue.hq_lock);
}

static inline struct host_queue_packet *hsa_queue_get_pkt(struct hsa_queue *queue, u64 slot)
{
	return &queue->hq_entry[slot & (queue->hq_header.capacity - 1)];
}

static void *get_host_queue_pkt(struct amdxdna_ctx *hwctx, u64 *seq, int *err)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct host_queue_packet *pkt;

	pkt = hsa_queue_reserve_slot(xdna, hwctx->priv, seq);
	if (IS_ERR(pkt)) {
		*err = PTR_ERR(pkt);
		/* Expected during retry - use DBG level */
		XDNA_DBG(xdna, "No slot available in Host queue (err=%d)", *err);
		return NULL;
	}

	*err = 0;
	return pkt;
}

static inline void hsa_queue_pkt_set_invalid(struct host_queue_packet *pkt)
{
	pkt->xrt_header.common_header.type = HOST_QUEUE_PACKET_TYPE_INVALID;
}

static void ve2_free_hsa_queue(struct amdxdna_dev *xdna, struct ve2_hsa_queue *queue)
{
	if (queue->hsa_queue_p) {
		XDNA_DBG(xdna, "Freeing host queue: dma_addr=0x%llx",
			 queue->hsa_queue_mem.dma_addr);
		dma_free_coherent(queue->alloc_dev,
				  sizeof(struct hsa_queue) + sizeof(u64) * HOST_QUEUE_ENTRY,
				  queue->hsa_queue_p,
				  queue->hsa_queue_mem.dma_addr);
		queue->hsa_queue_p = NULL;
		queue->hsa_queue_mem.dma_addr = 0;
		queue->alloc_dev = NULL;
		mutex_destroy(&queue->hq_lock);
	}
}

void packet_dump(struct amdxdna_dev *xdna, struct hsa_queue *queue, u64 slot_id)
{
	if (slot_id >= HOST_QUEUE_ENTRY) {
		XDNA_ERR(xdna, "Invalid slot_id: %llu\n", slot_id);
		return;
	}

	/* Print physical addresses */
	XDNA_DBG(xdna, "hsa dma_addr data 0x%llx\n", queue->hq_header.data_address);

	/* Print host_queue_packet */
	struct host_queue_packet *pkt = &queue->hq_entry[slot_id];

	XDNA_DBG(xdna, "Packet Dump for slot_id %llu:\n", slot_id);
	XDNA_DBG(xdna, "xrt_header.common_header.opcode: %u\n",
		 pkt->xrt_header.common_header.opcode);
	XDNA_DBG(xdna, "xrt_header.common_header.count: %u\n",
		 pkt->xrt_header.common_header.count);
	XDNA_DBG(xdna, "xrt_header.common_header.distribute: %u\n",
		 pkt->xrt_header.common_header.distribute);
	XDNA_DBG(xdna, "xrt_header.common_header.indirect: %u\n",
		 pkt->xrt_header.common_header.indirect);
	XDNA_DBG(xdna, "xrt_header.completion_signal: %llx\n",
		 pkt->xrt_header.completion_signal);
	for (int i = 0; i < 12; i++)
		XDNA_DBG(xdna, "\tdata[%d]: %x\n", i, (u32)pkt->data[i]);

	/* Print physical address of host_queue_packet */
	u64 pkt_paddr = queue->hq_header.data_address + ((u64)pkt - (u64)queue->hq_entry);

	XDNA_DBG(xdna, "Physical address of host_queue_packet: 0x%llx\n", pkt_paddr);

	/* Print host_queue_indirect_hdr */
	struct host_queue_indirect_hdr *indirect_hdr = &queue->hq_indirect_hdr[slot_id];
	int total_entry = indirect_hdr->header.count / sizeof(struct host_indirect_packet_entry);

	XDNA_DBG(xdna, "indirect_hdr.header.opcode: %u\n", indirect_hdr->header.opcode);
	XDNA_DBG(xdna, "indirect_hdr.header.count: %u\n", indirect_hdr->header.count);
	XDNA_DBG(xdna, "indirect_hdr.header.distribute: %u\n", indirect_hdr->header.distribute);
	XDNA_DBG(xdna, "indirect_hdr.header.indirect: %u\n", indirect_hdr->header.indirect);
	XDNA_DBG(xdna, "Total packet Entry %d\n", total_entry);
	for (int i = 0; i < 2 * total_entry; i += 2) {
		XDNA_DBG(xdna, "\tindirect_hdr.data[%d]: %x, indirect_hdr.data[%d]: %x\n",
			 i, (u32)indirect_hdr->data[i], i + 1,
			 (u32)(indirect_hdr->data[i + 1] & 0x1FFFFFF));
		XDNA_DBG(xdna, "Retrieved dpu_uc_index: %u\n",
			 (indirect_hdr->data[i + 1] >> 25) & 0x7F);
	}

	/* Print physical address of host_queue_indirect_hdr */
	u64 indirect_hdr_paddr = queue->hq_header.data_address +
			((u64)indirect_hdr - (u64)queue->hq_entry);
	XDNA_DBG(xdna, "Physical addr of host_queue_indirect_hdr: 0x%llx\n", indirect_hdr_paddr);

	/* Print host_queue_indirect_pkt */
	for (int i = 0; i < total_entry; i++) {
		struct host_queue_indirect_pkt *indirect_pkt = &queue->hq_indirect_pkt[i][slot_id];

		/* Print physical address of host_queue_indirect_pkt */
		u64 indirect_pkt_paddr = queue->hq_header.data_address +
			((u64)indirect_pkt - (u64)queue->hq_entry);

		XDNA_DBG(xdna, "\nPhysical address of indirect_pkt[%d]: 0x%llx\n", i,
			 indirect_pkt_paddr);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].header.opcode: %u\n",
			 i, indirect_pkt->header.opcode);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].header.count: %u\n",
			 i, indirect_pkt->header.count);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].header.distribute: %u\n",
			 i, indirect_pkt->header.distribute);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].header.indirect: %u\n",
			 i, indirect_pkt->header.indirect);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].payload.dpu_control_code_host_addr_low: %x\n",
			 i, (u32)indirect_pkt->payload.dpu_control_code_host_addr_low);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].payload.dpu_control_code_host_addr_high: %x\n",
			 i, (u32)indirect_pkt->payload.dpu_control_code_host_addr_high);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].payload.args_len: %u\n",
			 i, indirect_pkt->payload.args_len);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].payload.args_host_addr_low: %x\n",
			 i, (u32)indirect_pkt->payload.args_host_addr_low);
		XDNA_DBG(xdna, "\t\tindirect_pkt[%d].payload.args_host_addr_high: %x\n",
			 i, (u32)indirect_pkt->payload.args_host_addr_high);
	}
}

/*
 * Create hsa queue in kernel and initialize queue slots.
 */
static int ve2_create_host_queue(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx,
				 struct ve2_hsa_queue *queue)
{
	int nslots = HOST_QUEUE_ENTRY;
	struct device *alloc_dev;
	dma_addr_t dma_handle;
	size_t alloc_size;
	unsigned int r;

	alloc_size = sizeof(struct hsa_queue) + sizeof(u64) * nslots;
	XDNA_DBG(xdna, "Creating host queue: nslots=%d, alloc_size=%zu", nslots, alloc_size);

	/* Allocate from context's CMA region(s); try bitmap order (region 0, 1, ...). */
	for (r = 0; r < MAX_MEM_REGIONS; r++) {
		alloc_dev = xdna->cma_region_devs[r];
		if ((hwctx->priv->mem_bitmap & (1U << r)) && alloc_dev) {
			queue->hsa_queue_p = dma_alloc_coherent(alloc_dev, alloc_size,
								&dma_handle, GFP_KERNEL);
			if (!queue->hsa_queue_p)
				continue;
			queue->alloc_dev = alloc_dev;
			break;
		}
	}

	/* If no allocation succeeded, use the default device */
	if (!queue->hsa_queue_p) {
		queue->hsa_queue_p = dma_alloc_coherent(xdna->ddev.dev,
							alloc_size,
							&dma_handle,
							GFP_KERNEL);
		if (!queue->hsa_queue_p) {
			XDNA_ERR(xdna, "Failed to allocate host queue memory, size=%zu",
				 alloc_size);
			return -ENOMEM;
		}
		queue->alloc_dev = xdna->ddev.dev;
	}

	/* Initialize mutex here */
	mutex_init(&queue->hq_lock);
	/* Initialize reserved_write_index to track slot reservations */
	queue->reserved_write_index = 0;
	/* Set the base DMA address for hsa queue */
	queue->hsa_queue_mem.dma_addr = dma_handle;

	/* Calculate the address for hqc_mem within the allocated block */
	queue->hq_complete.hqc_mem = (u64 *)((char *)queue->hsa_queue_p + sizeof(struct hsa_queue));
	queue->hq_complete.hqc_dma_addr = queue->hsa_queue_mem.dma_addr + sizeof(struct hsa_queue);
	queue->hsa_queue_p->hq_header.data_address = queue->hsa_queue_mem.dma_addr +
		sizeof(struct host_queue_header);

	WARN_ON(!is_power_of_2(nslots));
	queue->hsa_queue_p->hq_header.capacity = nslots;

	/* Set hsa queue slots to invalid and initialize indirect regions */
	for (int slot = 0; slot < nslots; slot++) {
		struct host_queue_indirect_hdr *hdr = &queue->hsa_queue_p->hq_indirect_hdr[slot];

		hsa_queue_pkt_set_invalid(hsa_queue_get_pkt(queue->hsa_queue_p, slot));
		hdr->header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
		hdr->header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
		hdr->header.count = 0;
		hdr->header.distribute = 1;
		hdr->header.indirect = 1;

		for (int uc = 0; uc < HOST_INDIRECT_PKT_NUM; uc++) {
			struct host_queue_indirect_pkt *pkt =
				&queue->hsa_queue_p->hq_indirect_pkt[uc][slot];

			pkt->header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
			pkt->header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
			pkt->header.count = sizeof(struct exec_buf);
			pkt->header.distribute = 1;
			pkt->header.indirect = 0;
		}
	}

	/* Sync entire queue structure after initialization (device will read) */
	dma_sync_single_for_device(queue->alloc_dev,
				   queue->hsa_queue_mem.dma_addr,
				   sizeof(struct hsa_queue),
				   DMA_TO_DEVICE);

	XDNA_DBG(xdna, "Created host queue: dma_addr=0x%llx, capacity=%d, data_addr=0x%llx",
		 queue->hsa_queue_mem.dma_addr, nslots,
		 queue->hsa_queue_p->hq_header.data_address);

	return 0;
}

static int submit_command_indirect(struct amdxdna_ctx *hwctx, void *cmd_data, u64 *seq,
				   bool last_cmd)
{
	struct amdxdna_ctx_priv *ve2_ctx = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_hsa_queue *hq_queue;
	struct xrt_packet_header *hdr;
	struct host_queue_packet *pkt;
	struct ve2_dpu_data *dpu;
	struct hsa_queue *queue;
	u64 slot_id = 0;

	dpu = (struct ve2_dpu_data *)cmd_data;

	pkt = hsa_queue_reserve_slot(xdna, ve2_ctx, &slot_id);
	if (IS_ERR(pkt)) {
		XDNA_DBG(xdna, "No slot available in Host queue");
		return PTR_ERR(pkt);
	}

	hq_queue = (struct ve2_hsa_queue *)&ve2_ctx->hwctx_hsa_queue;
	queue = (struct hsa_queue *)hq_queue->hsa_queue_p;

	*seq = slot_id;
	XDNA_DBG(xdna, "slot %llx is selected", slot_id);
	slot_id = slot_id & (queue->hq_header.capacity - 1);

	hdr = &pkt->xrt_header;
	hdr->common_header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
	hdr->common_header.chain_flag = last_cmd ? LAST_CMD : NOT_LAST_CMD;
	hdr->common_header.count = sizeof(struct host_indirect_packet_entry);
	hdr->common_header.distribute = 1;
	hdr->common_header.indirect = 1;
	hdr->completion_signal = (u64)(hq_queue->hq_complete.hqc_dma_addr + slot_id * sizeof(u64));

	struct host_queue_indirect_hdr *indirect_hdr =
		(struct host_queue_indirect_hdr *)&queue->hq_indirect_hdr[slot_id];
	u32 total_cmds = dpu->chained + 1;

	indirect_hdr->header.count = total_cmds * sizeof(struct host_indirect_packet_entry);
	indirect_hdr->header.indirect = 1;
	indirect_hdr->header.distribute = 1;
	u64 m_indirect_hdr_paddr = (u64)(queue->hq_header.data_address +
			((u64)&queue->hq_indirect_hdr[slot_id] - (u64)&queue->hq_entry));

	struct host_indirect_packet_entry *hp = (struct host_indirect_packet_entry *)pkt->data;

	hp->host_addr_low = lower_32_bits((u64)m_indirect_hdr_paddr);
	hp->host_addr_high = upper_32_bits((u64)m_indirect_hdr_paddr);
	hp->uc_index = 0;

	struct host_indirect_packet_entry *hp_hdr =
		(struct host_indirect_packet_entry *)indirect_hdr->data;

	for (int i = 0; dpu && (i < total_cmds); i++, hp_hdr++, dpu = get_ve2_dpu_data_next(dpu)) {
		u16 uc = dpu->uc_index;
		struct host_queue_indirect_pkt *indirect_data =
			(struct host_queue_indirect_pkt *)&queue->hq_indirect_pkt[uc][slot_id];
		u64 m_indirect_data_paddr = (u64)(queue->hq_header.data_address +
				((u64)&queue->hq_indirect_pkt[uc][slot_id] -
				 (u64)&queue->hq_entry));

		XDNA_DBG(xdna, "\nIndirect packet id %d\n", i);
		XDNA_DBG(xdna, "\tuc index %d\n", uc);
		XDNA_DBG(xdna, "\tdpu instruction_buffer %llx\n", (u64)dpu->instruction_buffer);

		hp_hdr->host_addr_low = lower_32_bits((u64)m_indirect_data_paddr);
		hp_hdr->host_addr_high = upper_32_bits((u64)m_indirect_data_paddr);
		hp_hdr->uc_index = uc;

		struct host_queue_indirect_pkt *cebp = indirect_data;

		cebp->payload.dpu_control_code_host_addr_low =
			lower_32_bits(dpu->instruction_buffer);
		cebp->payload.dpu_control_code_host_addr_high =
			upper_32_bits(dpu->instruction_buffer);
		cebp->payload.dtrace_buf_host_addr_high = upper_32_bits(dpu->dtrace_buffer);
		cebp->payload.dtrace_buf_host_addr_low = lower_32_bits(dpu->dtrace_buffer);
		XDNA_DBG(xdna, "indirect[%d] dtrace addr: 0x%llx", i, dpu->dtrace_buffer);
		cebp->payload.args_len = 0;
		cebp->payload.args_host_addr_low = 0;
		cebp->payload.args_host_addr_high = 0;
		/* Sync indirect packet after writing (device will read) */
		hsa_queue_sync_indirect_pkt_for_write(hq_queue, uc, slot_id);
	}

	/* Sync packet after writing (device will read) */
	hsa_queue_sync_packet_for_write(hq_queue, slot_id);
	/* Sync indirect header after writing (device will read) */
	hsa_queue_sync_indirect_hdr_for_write(hq_queue, slot_id);

	/* Enable for debug purpose */
	if (verbosity >= VERBOSITY_LEVEL_DBG)
		packet_dump(xdna, queue, slot_id);

	/* Commit the slot - this sets hqc_mem to SUBMITTED and advances write_index */
	hsa_queue_commit_slot(xdna, ve2_ctx, *seq);

	return 0;
}

static int submit_command(struct amdxdna_ctx *hwctx, void *cmd_data, u64 *seq, bool last_cmd)
{
	struct amdxdna_ctx_priv *ve2_ctx = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct ve2_hsa_queue *hq_queue = &ve2_ctx->hwctx_hsa_queue;
	struct ve2_dpu_data *dpu_cmd;
	struct xrt_packet_header *hdr;
	struct host_queue_packet *pkt;
	struct exec_buf *ebp;
	u64 slot_id = 0;
	int err;

	if (!cmd_data) {
		XDNA_ERR(xdna, "Invalid command requested");
		return -EINVAL;
	}

	pkt = (struct host_queue_packet *)get_host_queue_pkt(hwctx, &slot_id, &err);
	if (!pkt) {
		/* Expected during retry - use DBG level */
		XDNA_DBG(xdna, "Getting host queue packet failed (err=%d)", err);
		return err;
	}

	*seq = slot_id;
	XDNA_DBG(xdna, "pkt %p of slot %llx is selected", (void *)pkt, slot_id);
	slot_id = slot_id & (hq_queue->hsa_queue_p->hq_header.capacity - 1);

	hdr = &pkt->xrt_header;
	hdr->common_header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
	hdr->common_header.chain_flag = last_cmd ? LAST_CMD : NOT_LAST_CMD;
	hdr->completion_signal =
		(u64)(hq_queue->hq_complete.hqc_dma_addr + slot_id * sizeof(u64));
#define XRT_PKT_OPCODE(p) ((p)->xrt_header.common_header.opcode)
	XDNA_DBG(xdna, "Queue packet opcode: %u\n", XRT_PKT_OPCODE(pkt));

	hdr->common_header.count = sizeof(struct exec_buf);
	hdr->common_header.distribute = 0;
	hdr->common_header.indirect = 0;

	dpu_cmd = (struct ve2_dpu_data *)cmd_data;
	ebp = (struct exec_buf *)pkt->data;
	ebp->dpu_control_code_host_addr_high = upper_32_bits(dpu_cmd->instruction_buffer);
	ebp->dpu_control_code_host_addr_low = lower_32_bits(dpu_cmd->instruction_buffer);

	ebp->dtrace_buf_host_addr_high = upper_32_bits(dpu_cmd->dtrace_buffer);
	ebp->dtrace_buf_host_addr_low = lower_32_bits(dpu_cmd->dtrace_buffer);

	ebp->args_len = 0;
	ebp->args_host_addr_low = 0;
	ebp->args_host_addr_high = 0;
	XDNA_DBG(xdna, "dpu instruction addr: 0x%llx", dpu_cmd->instruction_buffer);

	/* Sync packet after writing (device will read) */
	hsa_queue_sync_packet_for_write(hq_queue, slot_id);

	/* Commit the slot - this sets hqc_mem to SUBMITTED and advances write_index */
	hsa_queue_commit_slot(xdna, ve2_ctx, *seq);

	return 0;
}

static int ve2_submit_cmd_single(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	u32 cmd_data_len;
	void *cmd_data;
	int ret;

	cmd_data = amdxdna_cmd_get_payload(cmd_bo, &cmd_data_len);
	if (!cmd_data) {
		XDNA_ERR(xdna, "Invalid command received in single cmd submit");
		return -EINVAL;
	}

	while (true) {
		if (get_ve2_dpu_data_next(cmd_data))
			ret = submit_command_indirect(hwctx, cmd_data, seq, true);
		else
			ret = submit_command(hwctx, cmd_data, seq, true);

		if (ret != -EBUSY)
			break;

		XDNA_DBG(xdna, "Queue full, waiting for slot to become available (IRQ-driven)");

		ret = ve2_wait_for_retry_slot(hwctx, VE2_RETRY_TIMEOUT_MS);
		if (ret == -ETIMEDOUT) {
			XDNA_DBG(xdna, "Submit timeout: no slot available after %ums",
				 VE2_RETRY_TIMEOUT_MS);
			return -EAGAIN;
		} else if (ret < 0) {
			XDNA_ERR(xdna, "Submit interrupted while waiting for slot");
			return ret;
		}

		XDNA_DBG(xdna, "Slot available, retrying single command submission");
	}

	if (ret) {
		XDNA_ERR(xdna, "Submit single command failed, error %d", ret);
		return ret;
	}

	return ve2_hwctx_add_job(hwctx, job, *seq, 1);
}

/*
 * ve2_submit_cmd_chain_partial - Submit commands from a chain starting at start_idx
 * @hwctx: Hardware context
 * @job: Job containing the command chain
 * @start_idx: Index to start submitting from
 * @seq: Output sequence number (set to last submitted command's slot)
 * @submitted_count: Output count of successfully submitted commands
 *
 * Returns:
 *   0 on success (all remaining commands submitted)
 *   -EBUSY if queue became full (partial submission, check submitted_count)
 *   Other negative error codes on failure
 */
static int ve2_submit_cmd_chain_partial(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job,
					u32 start_idx, u64 *seq, u32 *submitted_count)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	struct amdxdna_cmd_chain *cmd_chain;
	u32 cmd_chain_len;
	int ret = 0;

	*submitted_count = 0;

	cmd_chain = amdxdna_cmd_get_payload(cmd_bo, &cmd_chain_len);
	if (!cmd_chain || cmd_chain_len < struct_size(cmd_chain, data, cmd_chain->command_count)) {
		XDNA_ERR(xdna, "Invalid command received in cmd chain submit");
		return -EINVAL;
	}

	for (u32 i = start_idx; i < cmd_chain->command_count; i++) {
		u32 boh = (u32)(cmd_chain->data[i]);
		struct amdxdna_gem_obj *abo;
		bool last_cmd = false;
		u32 cmd_data_len;
		void *cmd_data;

		abo = amdxdna_gem_get_obj(hwctx->client, boh, AMDXDNA_BO_SHARE);
		if (!abo) {
			XDNA_ERR(xdna, "Failed to find cmd BO %d", boh);
			return -ENOENT;
		}

		cmd_data = amdxdna_cmd_get_payload(abo, &cmd_data_len);
		if (!cmd_data) {
			XDNA_ERR(xdna, "Invalid command data received");
			amdxdna_gem_put_obj(abo);
			return -EINVAL;
		}

		if (i == cmd_chain->command_count - 1)
			last_cmd = true;
		if (get_ve2_dpu_data_next(cmd_data))
			ret = submit_command_indirect(hwctx, cmd_data, seq, last_cmd);
		else
			ret = submit_command(hwctx, cmd_data, seq, last_cmd);

		amdxdna_gem_put_obj(abo);

		if (ret == -EBUSY) {
			/* Queue full - return with partial count for retry */
			XDNA_DBG(xdna, "Queue full at cmd %u/%u", i, cmd_chain->command_count);
			return -EBUSY;
		} else if (ret) {
			XDNA_ERR(xdna, "Submit chain command(%u/%u) failed, error %d", i,
				 cmd_chain->command_count, ret);
			return ret;
		}

		(*submitted_count)++;
	}

	return 0;
}

static int ve2_submit_cmd_chain(struct amdxdna_ctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	struct amdxdna_cmd_chain *cmd_chain;
	u32 total_submitted = 0;
	u32 submitted_count = 0;
	u32 start_idx = 0;
	int ret;

	cmd_chain = amdxdna_cmd_get_payload(cmd_bo, NULL);
	if (!cmd_chain) {
		XDNA_ERR(xdna, "Invalid command chain");
		return -EINVAL;
	}

	while (start_idx < cmd_chain->command_count) {
		ret = ve2_submit_cmd_chain_partial(hwctx, job, start_idx, seq, &submitted_count);

		if (ret == 0) {
			total_submitted += submitted_count;
			break;
		} else if (ret == -EBUSY) {
			total_submitted += submitted_count;
			start_idx += submitted_count;

			XDNA_DBG(xdna,
				 "Queue full at cmd %u/%u, waiting for slot (IRQ-driven)",
				 start_idx, cmd_chain->command_count);

			ret = ve2_wait_for_retry_slot(hwctx, VE2_RETRY_TIMEOUT_MS);
			if (ret == -ETIMEDOUT) {
				XDNA_DBG(xdna,
					 "Submit chain timeout: no slot available after %ums (%u/%u cmds done)",
					 VE2_RETRY_TIMEOUT_MS, total_submitted,
					 cmd_chain->command_count);
				if (total_submitted > 0) {
					ve2_hwctx_add_job(hwctx, job, *seq, total_submitted);
					amdxdna_cmd_set_state(cmd_bo, ERT_CMD_STATE_TIMEOUT);
				}
				return -EAGAIN;
			} else if (ret < 0) {
				XDNA_ERR(xdna, "Submit chain interrupted while waiting for slot");
				if (total_submitted > 0)
					ve2_hwctx_add_job(hwctx, job, *seq, total_submitted);
				return ret;
			}

			XDNA_DBG(xdna,
				 "Slot available, retrying chain submission from cmd %u/%u",
				 start_idx, cmd_chain->command_count);
		} else {
			XDNA_ERR(xdna, "Submit chain failed with error %d (%u/%u cmds done)",
				 ret, total_submitted, cmd_chain->command_count);
			if (total_submitted > 0)
				ve2_hwctx_add_job(hwctx, job, *seq, total_submitted);
			return ret;
		}
	}

	return ve2_hwctx_add_job(hwctx, job, *seq, cmd_chain->command_count);
}

int ve2_cmd_submit(struct amdxdna_sched_job *job, u32 *syncobj_hdls,
		   u64 *syncobj_points, u32 syncobj_cnt, u64 *seq)
{
	struct amdxdna_ctx *hwctx = job->ctx;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_gem_obj *cmd_bo = job->cmd_bo;
	int ret;
	u32 op;

	op = amdxdna_cmd_get_op(cmd_bo);
	XDNA_DBG(xdna, "hwctx %p cmd_submit: op=%u (%s), syncobj_cnt=%u",
		 hwctx, op, op == ERT_CMD_CHAIN ? "CHAIN" : "SINGLE", syncobj_cnt);

	if (hwctx->priv->misc_intrpt_flag) {
		XDNA_ERR(xdna, "Failed to submit a command, because of misc interrupt\n");
		return -EINVAL;
	}

	if (op != ERT_START_DPU && op != ERT_CMD_CHAIN) {
		XDNA_WARN(xdna, "Unsupported ERT cmd: %d received", op);
		return -EINVAL;
	}

	if (op == ERT_CMD_CHAIN)
		ret = ve2_submit_cmd_chain(hwctx, job, seq);
	else
		ret = ve2_submit_cmd_single(hwctx, job, seq);

	if (ret) {
		/* Return -ERESTARTSYS for -EAGAIN so userspace can retry */
		if (ret == -EAGAIN) {
			XDNA_ERR(xdna, "Failed to submit a command (retry expected)\n");
			return -ERESTARTSYS;
		}

		XDNA_ERR(xdna, "Failed to submit a command. ret %d\n", ret);
		return ret;
	}

	XDNA_DBG(xdna, "hwctx %p cmd submitted: seq=%llu, total_submitted=%llu",
		 hwctx, *seq, hwctx->submitted);
	/* command_index = read_index when this job completes (last_slot + 1) */
	ve2_mgmt_schedule_cmd(xdna, hwctx, *seq + 1);

	return 0;
}

/*
 * Handle interrupt notification based on read_index and write_index.
 */
static inline bool check_read_index(struct amdxdna_ctx *hwctx,
				    u64 seq, u32 print_interval)
{
	struct amdxdna_ctx_priv *priv_ctx = hwctx->priv;
	static u64 counter;
	u64 *read_index;

	if (!hwctx || !priv_ctx || !priv_ctx->hwctx_hsa_queue.hsa_queue_p)
		return false;

	if (priv_ctx->misc_intrpt_flag)
		return true;

	read_index = (u64 *)((char *)priv_ctx->hwctx_hsa_queue.hsa_queue_p +
			HSA_QUEUE_READ_INDEX_OFFSET);

	/* Sync read_index before reading (device may have written) */
	hsa_queue_sync_read_index_for_read(&priv_ctx->hwctx_hsa_queue);

	if (counter % print_interval == 0) {
		struct amdxdna_dev *xdna = hwctx->client->xdna;

		XDNA_DBG(xdna, "read index address: 0x%llx", (u64)read_index);
		XDNA_DBG(xdna, "hwctx [%p] check read idx (%llu) > cmd idx (%llu)",
			 hwctx, *read_index, seq);
	}

	counter++;
	return (*read_index > seq);
}

static void ve2_dump_ctx(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx)
{
	struct amdxdna_ctx_priv *priv_ctx = hwctx->priv;
	struct device *aie_dev = priv_ctx->aie_dev;
	struct amdxdna_ctx_health_data_aie4 *r;
	struct handshake *hs = NULL;
	int ret = 0;

	r = kzalloc(sizeof(*r) + priv_ctx->num_col * sizeof(struct uc_health_info), GFP_KERNEL);
	if (!r) {
		XDNA_ERR(xdna, "No memory for struct amdxdna_ctx_health_data_aie4\n");
		return;
	}

	for (u32 col = 0; col < priv_ctx->num_col; col++) {
		hs = kzalloc(sizeof(*hs), GFP_KERNEL);
		if (!hs) {
			XDNA_ERR(xdna, "No memory for handshake.\n");
			kfree(r);
			return;
		}
		ret = ve2_partition_read_privileged_mem(aie_dev, col,
							offsetof(struct handshake, mpaie_alive),
							sizeof(struct handshake), (void *)hs);

		if (ret < 0) {
			XDNA_ERR(xdna, "aie_partition_read failed with ret=%d\n", ret);
			kfree(hs);
			kfree(r);
			return;
		}

		r->uc_info[col].uc_idx = hwctx->start_col + col;
		r->uc_info[col].page_idx = hs->vm.abs_page_index;
		r->uc_info[col].offset = hs->vm.ppc;
		r->uc_info[col].uc_idle_status = hs->cert_idle_status;
		r->uc_info[col].misc_status = hs->misc_status;
		r->uc_info[col].uc_pc = hs->exception.pc;
		r->uc_info[col].uc_ear = hs->exception.ear;
		r->uc_info[col].uc_esr = hs->exception.esr;
		r->uc_info[col].fw_state = hs->vm.fw_state;
		kfree(hs);
	}

	hwctx->health_data.version = AMDXDNA_CTX_HEALTH_DATA_V1;
	hwctx->health_data.npu_gen = AMDXDNA_NPU_GEN_AIE4;
	hwctx->health_data.aie4.ctx_state = priv_ctx->state;
	hwctx->health_data.aie4.num_uc = priv_ctx->num_col;
	memcpy(hwctx->health_data.aie4.uc_info, r->uc_info, priv_ctx->num_col *
	       sizeof(struct uc_health_info));

	kfree(r);
}

int ve2_cmd_wait(struct amdxdna_ctx *hwctx, u64 seq, u32 timeout)
{
	struct amdxdna_ctx_priv *priv_ctx = hwctx->priv;
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_sched_job *job;
	u32 print_interval = 300;
	unsigned long wait_jifs;
	int ret = 0;

	XDNA_DBG(xdna, "hwctx %p cmd_wait: seq=%llu, timeout=%u ms", hwctx, seq, timeout);

	/*
	 * NOTE: this is simplified hwctx which has no col_entry list for different ctx
	 * sharing the same lead col.
	 * The current version assumes one hwctx is 1:1 mapping with one lead cert col
	 */
	wait_jifs = msecs_to_jiffies(timeout);
	if (wait_jifs)
		ret = wait_event_interruptible_timeout(priv_ctx->waitq,
						       check_read_index(hwctx, seq, print_interval),
						       wait_jifs);
	else
		ret = wait_event_interruptible(priv_ctx->waitq,
					       check_read_index(hwctx, seq, print_interval));

	XDNA_DBG(xdna, "wait_event returned %d (timeout_jiffies=%lu)", ret, wait_jifs);

	mutex_lock(&priv_ctx->hwctx_hsa_queue.hq_lock);
	if ((!wait_jifs && !ret) || ret > 0) {
		mutex_lock(&priv_ctx->privctx_lock);
		job = ve2_hwctx_get_job(hwctx, seq);
		if (job)
			kref_get(&job->refcnt);
		mutex_unlock(&priv_ctx->privctx_lock);
		if (unlikely(!job)) {
			ret = 0;
			goto out;
		}

		/*
		 * below check need to be removed once we have a clean solution
		 * to use completion signal
		 */

		if (priv_ctx->misc_intrpt_flag || (wait_jifs && !ret)) {
			u32 capacity =
				priv_ctx->hwctx_hsa_queue.hsa_queue_p->hq_header.capacity;
			u32 start_slot = 0;
			u32 cmd_count = 1;
			void *cmd_data;
			u32 data_total;

			ve2_dump_ctx(xdna, hwctx);

			/* Read command_count BEFORE overwriting command buffer with health data */
			if (amdxdna_cmd_get_op(job->cmd_bo) == ERT_CMD_CHAIN) {
				struct amdxdna_cmd_chain *cc = amdxdna_cmd_get_payload(job->cmd_bo,
										       NULL);
				if (cc) {
					cmd_count = cc->command_count;
					/*
					 * seq is the LAST sequence number of the command chain.
					 * Calculate start_slot by going back (cmd_count - 1) slots.
					 */
					start_slot = (seq - cmd_count + 1) % capacity;
				}
			}

			cmd_data = amdxdna_cmd_get_data(job->cmd_bo, &data_total);
			size_t total_size = sizeof(struct amdxdna_ctx_health_data) +
					priv_ctx->num_col * sizeof(struct uc_health_info);
			if (unlikely(data_total < sizeof(hwctx->health_data)))
				XDNA_WARN(xdna, "%s: data_total: %u, sizeof(health): %lu", __func__,
					  data_total, total_size);

			data_total = min(data_total, total_size);
			memcpy(cmd_data, &hwctx->health_data, total_size);
			hwctx->health_reported = true;
			amdxdna_cmd_set_state(job->cmd_bo, ERT_CMD_STATE_TIMEOUT);

			if (amdxdna_cmd_get_op(job->cmd_bo) == ERT_CMD_CHAIN) {
				struct amdxdna_cmd_chain *cc = amdxdna_cmd_get_payload(job->cmd_bo,
										       NULL);
				XDNA_INFO(xdna, "start_slot %u, num_col %u, cmd_count %u",
					  start_slot, priv_ctx->num_col, cmd_count);
				if (!cc) {
					XDNA_WARN(xdna, "cmd_chain timeout: failed to get payload");
				} else {
					/* In the async callback/timeout case,
					 * driver sets error index to 0
					 */
					cc->error_index = 0;
				}
			}
		} else {
			u32 slot =
				seq % (priv_ctx->hwctx_hsa_queue.hsa_queue_p->hq_header.capacity);
			u64 *hqc_mem = priv_ctx->hwctx_hsa_queue.hq_complete.hqc_mem;
			u32 comp;
			enum ert_cmd_state state;

			/* Sync completion memory before reading (device may have written) */
			hsa_queue_sync_completion_for_read(&priv_ctx->hwctx_hsa_queue, slot);
			/* CERT encodes state in bits[3:0], error code in bits[31:4] (HSA_ERR) */
			comp = (u32)hqc_mem[slot];
			state = (enum ert_cmd_state)(comp & 0xF);
			if (state < ERT_CMD_STATE_NEW || state > ERT_CMD_STATE_NORESPONSE) {
				XDNA_WARN(xdna, "state %u at hqc_mem[%u] raw 0x%x",
					  state, slot, comp);
				goto release_job;
			}
			if ((state == ERT_CMD_STATE_ERROR || state == ERT_CMD_STATE_ABORT) &&
			    amdxdna_cmd_get_op(job->cmd_bo) == ERT_CMD_CHAIN) {
				u32 capacity =
					priv_ctx->hwctx_hsa_queue.hsa_queue_p->hq_header.capacity;
				struct amdxdna_cmd_chain *cc =
					amdxdna_cmd_get_payload(job->cmd_bo, NULL);
				/* Initialize to state to avoid undefined behavior */
				enum ert_cmd_state slot_state = state;
				u32 fail_cmd_idx = 0;
				u32 start_slot = 0;
				u32 cmd_count = 0;
				int i;

				if (!cc) {
					XDNA_WARN(xdna, "Failed to get payload, seq %llu", seq);
					amdxdna_cmd_set_state(job->cmd_bo, state);
					goto release_job;
				}
				cmd_count = cc->command_count;
				/*
				 * Runlist optimization: On failure, CERT sets ERROR (5) for the
				 * failing subcmd and ABORT (6) for all following subcmds. Per cert
				 * protocol: "searching backwards, the 1st cmd with completion
				 * status not ABORT is the one that failed".
				 */
				start_slot = (seq - cmd_count + 1) % capacity;

				XDNA_DBG(xdna, "seq %llu, start_slot %u, cmd_count %u", seq,
					 start_slot, cmd_count);

				for (i = cmd_count; i > 0; i--) {
					u32 slot = (start_slot + i - 1) % capacity;

					/* Sync completion memory before reading
					 * (device may have written)
					 */
					hsa_queue_sync_completion_for_read
						(&priv_ctx->hwctx_hsa_queue, slot);
					comp = (u32)hqc_mem[slot];
					slot_state = (enum ert_cmd_state)(comp & 0xF);
					if (slot_state != ERT_CMD_STATE_ABORT) {
						fail_cmd_idx = i - 1;
						break;
					}
				}

				cc->error_index = fail_cmd_idx;
				if (cc->error_index >= cmd_count)
					cc->error_index = 0;

				XDNA_ERR(xdna,
					 "Error at index %u (slot %u) slot_state %d err_code 0x%x",
					 fail_cmd_idx, (start_slot + fail_cmd_idx) % capacity,
					 slot_state,
					 slot_state == ERT_CMD_STATE_ERROR ? (comp >> 4) : 0);
				amdxdna_cmd_set_state(job->cmd_bo, slot_state);
			} else {
				amdxdna_cmd_set_state(job->cmd_bo, state);
			}
		}
release_job:
		ve2_hwctx_job_release_locked(hwctx, job);
		ve2_job_put(job);

		if (!wait_jifs) {
			mutex_unlock(&priv_ctx->hwctx_hsa_queue.hq_lock);
			return 0;
		}
	}

	/*
	 * wait_event_interruptible_timeout() returns 0 when the condition evaluated to false
	 * after the timeout elapsed. So, return -ETIME in this case
	 */
	if (!ret)
		ret = -ETIME;

out:
	mutex_unlock(&priv_ctx->hwctx_hsa_queue.hq_lock);
	XDNA_DBG(xdna, "wait_cmd ret:%d", ret);
	/* 0 is success, others are timeout */
	return ret > 0 ? 0 : ret;
}

static void timeout_cb(struct timer_list *t)
{
	struct amdxdna_ctx_priv *priv = from_timer(priv, t, event_timer);

	wake_up_interruptible_all(&priv->waitq);
	mod_timer(&priv->event_timer, jiffies + CTX_TIMER);
}

static void ve2_clear_firmware_status(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx)
{
	struct amdxdna_ctx_priv *priv = hwctx->priv;
	struct ve2_firmware_status *fs;

	for (u32 col = priv->start_col; col < priv->start_col + priv->num_col; col++) {
		fs = xdna->dev_handle->fw_slots[col];
		fs->state = 0;
		fs->abs_page_index = 0;
		fs->ppc = 0;
		fs->idle_status = 0;
		fs->misc_status = 0;
	}
}

int ve2_hwctx_init(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_ctx_priv *priv = NULL;
	int ret;

	XDNA_DBG(xdna, "Initializing hwctx for client pid %d, num_tiles=%u, priority=%u",
		 client->pid, hwctx->num_tiles, hwctx->qos.priority);

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	hwctx->priv = priv;
	init_waitqueue_head(&priv->waitq);

	ret = ve2_xrs_request(xdna, hwctx);
	if (ret) {
		XDNA_ERR(xdna, "XRS resource request failed, ret=%d", ret);
		goto cleanup_priv;
	}

	/* Auto-select memory bitmap based on start_col */
	ve2_auto_select_mem_bitmap(xdna, hwctx);

	/* One host_queue entry per hwctx */
	ret = ve2_create_host_queue(xdna, hwctx, &priv->hwctx_hsa_queue);
	if (ret) {
		XDNA_ERR(xdna, "Failed to create host queue, ret=%d", ret);
		goto cleanup_xrs;
	}

	if (enable_polling) {
		XDNA_DBG(xdna, "Running in timer mode");
		timer_setup(&priv->event_timer, timeout_cb, 0);
		mod_timer(&priv->event_timer, jiffies + CTX_TIMER);
	} else {
		XDNA_DBG(xdna, "Running in interrupt mode");
	}

	if (verbosity >= VERBOSITY_LEVEL_DBG)
		ve2_clear_firmware_status(xdna, hwctx);

	mutex_init(&priv->privctx_lock);
	priv->state = AMDXDNA_HWCTX_STATE_IDLE;

	XDNA_DBG(xdna, "hwctx %p initialized: start_col=%u, num_col=%u, queue_addr=0x%llx",
		 hwctx, priv->start_col, priv->num_col,
		 priv->hwctx_hsa_queue.hsa_queue_mem.dma_addr);

	return 0;

cleanup_xrs:
	/* Releases XRS and partition (ve2_mgmt_destroy_partition calls ve2_xrs_release). */
	ve2_mgmt_destroy_partition(hwctx);
cleanup_priv:
	kfree(hwctx->priv);

	return ret;
}

void ve2_hwctx_fini(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_mgmtctx *mgmtctx;
	struct amdxdna_sched_job *job;
	int idx;

	XDNA_DBG(xdna,
		 "Finalizing hwctx %p: start_col=%u, num_col=%u, submitted=%llu, completed=%llu",
		 hwctx, nhwctx->start_col, nhwctx->num_col,
		 hwctx->submitted, hwctx->completed);

	if (enable_polling)
		del_timer_sync(&hwctx->priv->event_timer);

	/*
	 * Clear active_ctx FIRST to prevent IRQ handler from queueing new work,
	 * remove all FIFO entries for this context to prevent use-after-free,
	 * then cancel any pending work to ensure no work is accessing this context
	 */
	mgmtctx = &xdna->dev_handle->ve2_mgmtctx[nhwctx->start_col];
	mutex_lock(&mgmtctx->ctx_lock);
	if (mgmtctx->active_ctx == hwctx)
		mgmtctx->active_ctx = NULL;
	/* Remove all FIFO entries for this context before freeing it */
	ve2_fifo_remove_ctx(mgmtctx, hwctx);
	mutex_unlock(&mgmtctx->ctx_lock);

	/* Now cancel any pending work - it will see active_ctx as NULL and bail out */
	if (mgmtctx->mgmtctx_workq)
		cancel_work_sync(&mgmtctx->sched_work);

	/*
	 * Release jobs first to decrement BO refcounts, but they may not
	 * be freed immediately if the application still holds references
	 */
	mutex_lock(&nhwctx->privctx_lock);
	for (idx = 0; idx < HWCTX_MAX_CMDS; idx++) {
		job = hwctx->priv->pending[idx];
		if (!job)
			continue;

		/*
		 * Release privctx_lock before calling ve2_hwctx_job_release
		 * as it will acquire the same lock internally.
		 * Take a reference to the job to ensure it's not freed.
		 */
		kref_get(&job->refcnt);
		mutex_unlock(&nhwctx->privctx_lock);
		ve2_hwctx_job_release(hwctx, job);
		ve2_job_put(job);
		mutex_lock(&nhwctx->privctx_lock);
	}
	mutex_unlock(&nhwctx->privctx_lock);

	if (verbosity >= VERBOSITY_LEVEL_DBG)
		ve2_get_firmware_status(hwctx);

	ve2_mgmt_destroy_partition(hwctx);
	ve2_free_hsa_queue(xdna, &hwctx->priv->hwctx_hsa_queue);
	kfree(hwctx->priv->hwctx_config);
	mutex_destroy(&hwctx->priv->privctx_lock);
	kfree(hwctx->priv);
	hwctx->priv = NULL;
	XDNA_DBG(xdna, "Destroyed hwctx %p, total cmds submitted (%llu), completed(%llu)",
		 hwctx, hwctx->submitted, hwctx->completed);
}

static int ve2_update_handshake_pkt(struct amdxdna_ctx *hwctx, u8 buf_type, u64 paddr,
				    u32 buf_sz, u32 col, bool attach)
{
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;

	switch (buf_type) {
	case AMDXDNA_FW_BUF_DEBUG:
		nhwctx->hwctx_config[col].debug_buf_addr = paddr;
		nhwctx->hwctx_config[col].debug_buf_size = buf_sz;
		break;

	case AMDXDNA_FW_BUF_TRACE:
		nhwctx->hwctx_config[col].dtrace_addr = paddr;
		break;

	case AMDXDNA_FW_BUF_LOG:
		nhwctx->hwctx_config[col].log_buf_addr = paddr;
		nhwctx->hwctx_config[col].log_buf_size = buf_sz;
		break;

	default:
		struct amdxdna_dev *xdna = hwctx->client->xdna;

		XDNA_ERR(xdna, "Invalid Request");
		return -EOPNOTSUPP;
	}

	return 0;
}

static void ve2_hwctx_config_op_timeout(struct amdxdna_ctx *hwctx, u32 op_timeout)
{
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;

	for (u32 col = 0; col < hwctx->num_col; col++)
		nhwctx->hwctx_config[col].opcode_timeout_config = op_timeout;
}

int ve2_hwctx_config(struct amdxdna_ctx *hwctx, u32 type, u64 mdata_hdl, void *buf, u32 size)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_gem_obj *abo, *mdata_abo = NULL;
	struct fw_buffer_metadata *mdata;
	u32 prev_buf_sz = 0;
	u32 op_timeout;
	u64 buf_paddr;
	u32 buf_sz;
	int ret = 0;

	XDNA_DBG(xdna, "hwctx %p config: type=%u, mdata_hdl=0x%llx, size=%u",
		 hwctx, type, mdata_hdl, size);

	/* Update fw's handshake shared memory with debug/trace buffer details */
	switch (type) {
	case DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF:
		mdata_abo = amdxdna_gem_get_obj(client, mdata_hdl, AMDXDNA_BO_SHARE);
		if (!mdata_abo || !mdata_abo->dma_buf) {
			XDNA_ERR(xdna, "%s: Failed to get metadata BO %lld for type %d",
				 __func__, mdata_hdl, type);
			return -EINVAL;
		}
		mdata = (struct fw_buffer_metadata *)(amdxdna_gem_vmap(mdata_abo));
		if (!mdata) {
			XDNA_ERR(xdna, "%s: Failed to vmap metadata BO %lld for type %d",
				 __func__, mdata_hdl, type);
			amdxdna_gem_put_obj(mdata_abo);
			return -EINVAL;
		}

		abo = amdxdna_gem_get_obj(client, mdata->bo_handle, AMDXDNA_BO_SHARE);
		if (!abo) {
			XDNA_ERR(xdna, "%s: Failed to get BO %lld for type %d",
				 __func__, mdata->bo_handle, type);
			amdxdna_gem_put_obj(mdata_abo);
			return -EINVAL;
		}

		for (u32 col = 0; col < hwctx->num_col; col++) {
			buf_sz = mdata->uc_info[col].size;
			if (buf_sz == 0)
				continue;
			buf_paddr = amdxdna_gem_dev_addr(abo) + prev_buf_sz;
			ret = ve2_update_handshake_pkt(hwctx, mdata->buf_type, buf_paddr, buf_sz,
						       col, true);
			if (ret) {
				XDNA_ERR(xdna, "%s: handshake pkt fail col=%u type=%d ret=%d",
					 __func__, col, mdata->buf_type, ret);
				amdxdna_gem_put_obj(abo);
				amdxdna_gem_put_obj(mdata_abo);
				return ret;
			}
			prev_buf_sz += buf_sz;
		}
		XDNA_DBG(xdna, "Attached buf_type %d BO %lld to hwctx %s",
			 mdata->buf_type, mdata->bo_handle, hwctx->name);

		amdxdna_gem_put_obj(abo);
		amdxdna_gem_put_obj(mdata_abo);
		ret = 0;
		break;

	case DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF:
		mdata_abo = amdxdna_gem_get_obj(client, mdata_hdl, AMDXDNA_BO_SHARE);
		if (!mdata_abo || !mdata_abo->dma_buf) {
			XDNA_ERR(xdna, "%s: Failed to get metadata BO %lld for type %d",
				 __func__, mdata_hdl, type);
			return -EINVAL;
		}
		mdata = (struct fw_buffer_metadata *)(amdxdna_gem_vmap(mdata_abo));
		if (!mdata) {
			XDNA_ERR(xdna, "%s: Failed to vmap metadata BO %lld for type %d",
				 __func__, mdata_hdl, type);
			amdxdna_gem_put_obj(mdata_abo);
			return -EINVAL;
		}
		for (u32 col = 0; col < hwctx->num_col; col++) {
			ret = ve2_update_handshake_pkt(hwctx, mdata->buf_type, 0, 0, col, false);
			if (ret) {
				XDNA_ERR(xdna,
					 "%s: detach fail type=%d BO=%lld ctx=%s col=%u ret=%d",
					 __func__, mdata->buf_type, mdata->bo_handle,
					 hwctx->name, col, ret);
				amdxdna_gem_put_obj(mdata_abo);
				return ret;
			}
		}
		XDNA_DBG(xdna, "Detached buf_type %d BO %lld from hwctx %s",
			 mdata->buf_type, mdata->bo_handle, hwctx->name);

		amdxdna_gem_put_obj(mdata_abo);
		ret = 0;
		break;

	case DRM_AMDXDNA_HWCTX_CONFIG_OPCODE_TIMEOUT:
		if (copy_from_user(&op_timeout, (u32 __user *)(uintptr_t)mdata_hdl, sizeof(u32))) {
			XDNA_ERR(xdna, "%s: Failed to copy opcode timeout from user", __func__);
			return -EFAULT;
		}

		ve2_hwctx_config_op_timeout(hwctx, op_timeout);
		XDNA_DBG(xdna, "Configured opcode timeout %u on hwctx %s",
			 op_timeout, hwctx->name);
		ret = 0;
		break;

	default:
		XDNA_ERR(xdna, "%s: Unsupported config type %d", __func__, type);
		return -EOPNOTSUPP;
	}

	return ret;
}
