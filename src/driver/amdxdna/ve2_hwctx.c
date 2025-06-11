// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#include <drm/drm_cache.h>
#include <linux/dma-mapping.h>

#include "amdxdna_ctx.h"
#include "amdxdna_gem_of.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_res_solver.h"

static inline struct host_queue_packet *hsa_queue_get_pkt(struct hsa_queue *queue, u64 slot)
{
	return &queue->hq_entry[slot & (queue->hq_header.capacity - 1)];
}

static inline void hsa_queue_pkt_set_invalid(struct host_queue_packet *pkt)
{
	pkt->xrt_header.common_header.type = HOST_QUEUE_PACKET_TYPE_INVALID;
}

static void ve2_free_hsa_queue(struct amdxdna_dev *xdna, struct ve2_hsa_queue *queue)
{
	struct platform_device *pdev = to_platform_device(xdna->ddev.dev);

	if (queue->hsa_queue_p) {
		dma_free_coherent(&pdev->dev, sizeof(struct hsa_queue), queue->hsa_queue_p,
				  queue->hsa_queue_mem.dma_addr);
		queue->hsa_queue_p = NULL;
	}
}

/*
 * Create hsa queue in kernel and initialize queue slots.
 */
static int ve2_create_host_queue(struct amdxdna_dev *xdna, struct ve2_hsa_queue *queue)
{
	struct platform_device *pdev = to_platform_device(xdna->ddev.dev);
	int nslots = HOST_QUEUE_ENTRY;
	dma_addr_t dma_handle;

	// Allocate a single contiguous block of memory
	queue->hsa_queue_p = dma_alloc_coherent(&pdev->dev,
						sizeof(struct hsa_queue) + sizeof(u64) * nslots,
						&dma_handle,
						GFP_KERNEL);
	if (!queue->hsa_queue_p)
		return -ENOMEM;

	// Set the base DMA address for hsa queue
	queue->hsa_queue_mem.dma_addr = dma_handle;

	// Calculate the address for hqc_mem within the allocated block
	queue->hq_complete.hqc_mem =
		(u64 *)((char *)queue->hsa_queue_p + sizeof(struct hsa_queue));
	queue->hq_complete.hqc_dma_addr = queue->hsa_queue_mem.dma_addr + sizeof(struct hsa_queue);
	queue->hsa_queue_p->hq_header.data_address = queue->hsa_queue_mem.dma_addr +
		sizeof(struct host_queue_header);

	// Set hsa queue slots to invalid
	for (int i = 0; i < nslots; i++) {
		struct host_queue_indirect_hdr *hdr = &queue->hsa_queue_p->hq_indirect_hdr[i];

		hsa_queue_pkt_set_invalid(hsa_queue_get_pkt(queue->hsa_queue_p, i));
		hdr->header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
		hdr->header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
		hdr->header.count = 0;
		hdr->header.distribute = 1;
		hdr->header.indirect = 1;

		for (int j = 0; j < HOST_INDIRECT_PKT_NUM; j++) {
			struct host_queue_indirect_pkt *pkt =
			       &queue->hsa_queue_p->hq_indirect_pkt[i][j];

			pkt->header.type = HOST_QUEUE_PACKET_TYPE_VENDOR_SPECIFIC;
			pkt->header.opcode = HOST_QUEUE_PACKET_EXEC_BUF;
			pkt->header.count = sizeof(struct exec_buf);
			pkt->header.distribute = 1;
			pkt->header.indirect = 0;
		}
	}

	WARN_ON(!is_power_of_2(nslots));
	queue->hsa_queue_p->hq_header.capacity = nslots;

	XDNA_DBG(xdna, "created ve2 hsq queue with capacity %d slots", nslots);
	return 0;
}

int ve2_hwctx_init(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_ctx_priv *priv = NULL;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	hwctx->priv = priv;

	/* one host_queue entry per hwctx */
	ret = ve2_create_host_queue(xdna, &priv->hwctx_hsa_queue);
	if (ret)
		goto free_priv;

	ret = ve2_mgmt_create_partition(xdna, hwctx);
	if (ret)
		goto free_hsa_queue;

	return 0;

free_hsa_queue:
	ve2_free_hsa_queue(xdna, &hwctx->priv->hwctx_hsa_queue);
free_priv:
	kfree(hwctx->priv);

	return ret;
}

void ve2_hwctx_fini(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_client *client = hwctx->client;
	struct amdxdna_dev *xdna = client->xdna;

	ve2_mgmt_destroy_partition(hwctx);
	ve2_free_hsa_queue(xdna, &hwctx->priv->hwctx_hsa_queue);
	kfree(hwctx->priv);
}
