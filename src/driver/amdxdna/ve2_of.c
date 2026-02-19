// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/xlnx-ai-engine.h>
#include <linux/of_reserved_mem.h>

#include "ve2_of.h"
#include "ve2_mgmt.h"

static int ve2_load_fw(struct amdxdna_dev_hdl *xdna_hdl)
{
	struct amdxdna_dev *xdna = xdna_hdl->xdna;
	struct aie_partition_init_args args;
	struct aie_partition_req request;
	const struct firmware *fw;
	struct device *xaie_dev;
	size_t buf_len;
	char *buf;
	int ret;

	XDNA_DBG(xdna, "Loading firmware: %s", xdna_hdl->priv->fw_path);

	ret = request_firmware(&fw, xdna_hdl->priv->fw_path, xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "request fw %s failed %d", xdna_hdl->priv->fw_path, ret);
		return -ENODEV;
	}

	XDNA_DBG(xdna, "Firmware loaded: size=%zu bytes", fw->size);

	buf = kmalloc(fw->size, GFP_KERNEL);
	if (!buf) {
		release_firmware(fw);
		return -ENOMEM;
	}
	memcpy(buf, fw->data, fw->size);
	buf_len = fw->size;
	release_firmware(fw);

	/* request all cols */
	xaie_dev = aie_partition_request(&request);
	if (IS_ERR(xaie_dev)) {
		ret = PTR_ERR(xaie_dev);
		XDNA_ERR(xdna, "aie partition request failed: %d", ret);
		goto out;
	}
	XDNA_DBG(xdna, "aie partition request succeeded: 0x%x", request.partition_id);

	args.locs = NULL;
	args.num_tiles = 0;
	args.handshake_cols = 0;
	args.handshake = NULL;
	args.init_opts = (AIE_PART_INIT_OPT_DEFAULT | AIE_PART_INIT_OPT_DIS_TLAST_ERROR)
	& ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;
	ret = ve2_partition_initialize(xaie_dev, &args);
	if (ret) {
		XDNA_ERR(xdna, "aie partition init failed: %d", ret);
		goto release;
	}

	ret = aie_load_cert_broadcast(xaie_dev, buf);
	if (ret) {
		XDNA_ERR(xdna, "aie load cert broadcast failed %d", ret);
		goto teardown;
	}
	XDNA_INFO(xdna, "aie load cert broadcast complete");

	ret = ve2_store_firmware_version(&xdna_hdl->fw_version, xaie_dev);
	if (ret < 0) {
		XDNA_ERR(xdna, "cert status read failed with err %d", ret);
		goto teardown;
	}
	XDNA_INFO(xdna, "CERT major: %d\n", xdna_hdl->fw_version.major);
	XDNA_INFO(xdna, "CERT minor: %d\n", xdna_hdl->fw_version.minor);
	XDNA_INFO(xdna, "CERT git hash: %s\n", xdna_hdl->fw_version.git_hash);
	XDNA_INFO(xdna, "CERT git hash date: %s\n", xdna_hdl->fw_version.date);

teardown:
	aie_partition_teardown(xaie_dev);
release:
	aie_partition_release(xaie_dev);
out:
	kfree(buf);
	return ret;
}

static void ve2_cma_device_release(struct device *dev)
{
	/*
	 * This is the device release callback invoked by put_device().
	 * The caller (ve2_cma_mem_region_remove) must call
	 * of_reserved_mem_device_release() to release DMA/reserved memory
	 * resources before calling put_device().
	 * This callback only frees the device structure allocated by kzalloc().
	 */
	kfree(dev);
}

static void ve2_cma_mem_region_remove(struct amdxdna_dev *xdna)
{
	int i;

	for (i = 0; i < MAX_MEM_REGIONS; i++) {
		struct device *dev = xdna->cma_region_devs[i];

		if (dev) {
			of_reserved_mem_device_release(dev);
			put_device(dev);
			xdna->cma_region_devs[i] = NULL;
		}
	}
}

static int
ve2_cma_mem_region_init(struct amdxdna_dev *xdna, struct device_node *aie_np)
{
	struct device *parent_dev = xdna->ddev.dev;
	struct device *child_dev;
	int num_regions;
	int ret;
	int i;

	num_regions = of_count_phandle_with_args(aie_np, "memory-region", NULL);
	if (num_regions <= 0 || num_regions > MAX_MEM_REGIONS)
		return -EINVAL;

	for (i = 0; i < num_regions && i < MAX_MEM_REGIONS; i++) {
		child_dev = kzalloc(sizeof(*child_dev), GFP_KERNEL);
		if (!child_dev) {
			XDNA_ERR(xdna,
				 "Failed to alloc child_dev for cma region %d",
				 i);
			ret = -ENOMEM;
			goto cleanup;
		}

		device_initialize(child_dev);
		child_dev->parent = parent_dev;
		child_dev->of_node = aie_np;
		child_dev->coherent_dma_mask = DMA_BIT_MASK(64);
		child_dev->release = ve2_cma_device_release;

		ret = dev_set_name(child_dev, "amdxdna-mem%d", i);
		if (ret) {
			XDNA_ERR(xdna,
				 "Failed to set name for cma region %d", i);
			goto put_dev;
		}

		ret = of_reserved_mem_device_init_by_idx(child_dev, aie_np, i);
		if (ret) {
			XDNA_ERR(xdna,
				 "Failed to init reserved cma region %d", i);
			goto put_dev;
		}

		xdna->cma_region_devs[i] = child_dev;
	}

	return 0;

put_dev:
	put_device(child_dev);
cleanup:
	ve2_cma_mem_region_remove(xdna);
	return ret;
}

/**
 * ve2_parse_mem_topology - Parse AIE memory topology from device tree
 * @xdna: Pointer to the device structure
 * @aie_np: AI engine device node (parent->of_node; has memory-region)
 *
 * Finds the aie_mem_topology node by compatible. Search starts from the
 * AI engine node's parent so the topology node is expected as a sibling.
 * Build phandle -> CMA index map from AI engine node's memory-region.
 * Each child defines columns = <start end> and one or more memory-region
 * phandles; phandles are resolved to CMA indices and stored as a bitmap.
 * Topology is stored as regions[0..num_regions-1], cap MAX_MEM_REGIONS.
 */
static int ve2_parse_mem_topology(struct amdxdna_dev *xdna,
				  struct device_node *aie_np)
{
	struct amdxdna_dev_hdl *xdna_hdl = xdna->dev_handle;
	struct device_node *aie_mem_nodes[MAX_MEM_REGIONS];
	struct device_node *mem_region_np;
	struct device_node *region_np;
	struct device_node *topo_np;
	u32 cma_region_bitmap;
	u32 cma_region_idx;
	u32 col_range[2];
	int num_phandles;
	int region_idx;
	int phandle_idx;
	int ret;

	topo_np = NULL;
	if (aie_np && aie_np->parent)
		topo_np = of_find_compatible_node(aie_np->parent, NULL,
						  "xlnx,aie-mem-topology");
	if (!topo_np) {
		XDNA_DBG(xdna, "No aie_mem_topology node found, using default CMA");
		xdna_hdl->mem_topology.num_regions = 0;
		return -ENOENT;
	}

	/* Build phandle -> CMA index map from AI engine node's memory-region */
	for (cma_region_idx = 0; cma_region_idx < MAX_MEM_REGIONS; cma_region_idx++)
		aie_mem_nodes[cma_region_idx] = of_parse_phandle(aie_np,
								 "memory-region",
								  cma_region_idx);

	xdna_hdl->mem_topology.num_regions = 0;

	for_each_child_of_node(topo_np, region_np) {
		if (xdna_hdl->mem_topology.num_regions >= MAX_MEM_REGIONS) {
			XDNA_DBG(xdna, "Too many topology entries, max %d", MAX_MEM_REGIONS);
			break;
		}

		ret = of_property_read_u32_array(region_np, "columns", col_range, 2);
		if (ret) {
			XDNA_DBG(xdna, "Failed to read columns property: %d", ret);
			continue;
		}

		if (col_range[0] > col_range[1] ||
		    col_range[1] >= xdna_hdl->aie_dev_info.cols) {
			XDNA_DBG(xdna, "Columns range %u-%u out of bounds (valid 0..%u)",
				 col_range[0], col_range[1],
				 xdna_hdl->aie_dev_info.cols - 1);
			continue;
		}

		num_phandles = of_count_phandle_with_args(region_np, "memory-region", NULL);
		if (num_phandles <= 0) {
			XDNA_DBG(xdna, "No memory-region phandles in region node");
			continue;
		}

		cma_region_bitmap = 0;
		for (phandle_idx = 0;
		     phandle_idx < (u32)num_phandles && phandle_idx < MAX_MEM_REGIONS;
		     phandle_idx++) {
			mem_region_np = of_parse_phandle(region_np, "memory-region", phandle_idx);
			if (!mem_region_np)
				continue;
			for (cma_region_idx = 0; cma_region_idx < MAX_MEM_REGIONS;
			     cma_region_idx++) {
				if (!aie_mem_nodes[cma_region_idx])
					break;
				if (aie_mem_nodes[cma_region_idx] == mem_region_np) {
					cma_region_bitmap |= (1U << cma_region_idx);
					break;
				}
			}
			of_node_put(mem_region_np);
		}

		if (cma_region_bitmap == 0) {
			XDNA_DBG(xdna, "No valid CMA phandles for cols %u-%u",
				 col_range[0], col_range[1]);
			continue;
		}

		region_idx = xdna_hdl->mem_topology.num_regions;
		xdna_hdl->mem_topology.regions[region_idx].start_col = col_range[0];
		xdna_hdl->mem_topology.regions[region_idx].end_col = col_range[1];
		xdna_hdl->mem_topology.regions[region_idx].mem_bitmap = cma_region_bitmap;
		xdna_hdl->mem_topology.num_regions++;

		XDNA_DBG(xdna, "Mem topology entry %u: cols %u-%u bitmap=0x%x",
			 region_idx, col_range[0], col_range[1], cma_region_bitmap);
	}

	for (cma_region_idx = 0; cma_region_idx < MAX_MEM_REGIONS; cma_region_idx++) {
		if (aie_mem_nodes[cma_region_idx])
			of_node_put(aie_mem_nodes[cma_region_idx]);
	}
	of_node_put(topo_np);
	return 0;
}

/**
 * ve2_auto_select_mem_bitmap - Auto-select memory bitmap based on start_col
 * @xdna: Pointer to the device structure
 * @hwctx: Hardware context (must be called AFTER ve2_xrs_request)
 *
 * Uses the ACTUAL allocated start_col (from XRS) and the parsed memory topology.
 * Stores the selected mem_bitmap in hwctx->priv->mem_bitmap.
 * If no topology or start_col not in any range, sets 0 (use default CMA).
 */
void ve2_auto_select_mem_bitmap(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx)
{
	struct amdxdna_dev_hdl *xdna_hdl = xdna->dev_handle;
	struct amdxdna_ctx_priv *priv = hwctx->priv;
	u32 start_col = priv->start_col;
	struct ve2_mem_topology *topo;
	u32 region_idx;

	if (!xdna_hdl) {
		priv->mem_bitmap = 0;
		return;
	}

	topo = &xdna_hdl->mem_topology;
	for (region_idx = 0; region_idx < topo->num_regions; region_idx++) {
		if (start_col >= topo->regions[region_idx].start_col &&
		    start_col <= topo->regions[region_idx].end_col) {
			priv->mem_bitmap = topo->regions[region_idx].mem_bitmap;
			XDNA_DBG(xdna, "Auto-selected mem_bitmap=0x%x for start_col=%u",
				 topo->regions[region_idx].mem_bitmap, start_col);
			return;
		}
	}

	XDNA_DBG(xdna, "No topology match for start_col=%u, using default CMA", start_col);
	priv->mem_bitmap = 0;
}

static int ve2_init(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;
	struct device_node *aie_np;
	struct ve2_firmware_status *fw_slots;
	struct init_config xrs_cfg = { 0 };
	struct amdxdna_dev_hdl *xdna_hdl;
	int ret;
	u32 col;

	XDNA_DBG(xdna, "Initializing VE2 device");

	xdna_hdl = devm_kzalloc(dev, sizeof(*xdna_hdl), GFP_KERNEL);
	if (!xdna_hdl)
		return -ENOMEM;

	xdna_hdl->xdna = xdna;
	xdna_hdl->priv = xdna->dev_info->dev_priv;
	xdna->dev_handle = xdna_hdl;

	if (ve2_hwctx_limit)
		xdna_hdl->hwctx_limit = ve2_hwctx_limit;
	else
		xdna_hdl->hwctx_limit = xdna_hdl->priv->hwctx_limit;

	XDNA_INFO(xdna, "Maximum limit %d hardware context(s)", xdna_hdl->hwctx_limit);

	ret = aie_get_device_info(&xdna_hdl->aie_dev_info);
	if (ret) {
		if (ret == -ENODEV) {
			XDNA_INFO(xdna, "AIE device not ready yet, deferring probe");
			return -EPROBE_DEFER;
		}
		XDNA_ERR(xdna, "Failed to get AIE device info, ret %d", ret);
		return ret;
	}
	XDNA_INFO(xdna, "AIE device: %d columns, %d rows",
		  xdna_hdl->aie_dev_info.cols, xdna_hdl->aie_dev_info.rows);

	xrs_cfg.ddev = &xdna->ddev;

	/* Support module parameters to override column count if valid */
	if (max_col > 0 && start_col >= 0 &&
	    (max_col + start_col) <= xdna_hdl->aie_dev_info.cols) {
		xrs_cfg.total_col = max_col;
		XDNA_INFO(xdna, "Using module parameter: max_col=%d, start_col=%d",
			  max_col, start_col);
	} else {
		xrs_cfg.total_col = xdna_hdl->aie_dev_info.cols;
	}

	xdna->dev_handle->xrs_hdl = xrsm_init(&xrs_cfg);
	if (!xdna->dev_handle->xrs_hdl) {
		XDNA_ERR(xdna, "Initialization of Resource resolver failed");
		return -EINVAL;
	}

	/* Load firmware */
	ret = ve2_load_fw(xdna_hdl);
	if (ret) {
		XDNA_ERR(xdna, "aie load %s failed with err %d", xdna_hdl->priv->fw_path, ret);
		return ret;
	}
	XDNA_DBG(xdna, "aie fw load %s completed", xdna_hdl->priv->fw_path);

	/* Allocate arrays based on actual column count from device */
	xdna_hdl->fw_slots = devm_kcalloc(dev, xdna_hdl->aie_dev_info.cols,
					  sizeof(*xdna_hdl->fw_slots), GFP_KERNEL);
	if (!xdna_hdl->fw_slots) {
		XDNA_ERR(xdna, "No memory for fw_slots array");
		return -ENOMEM;
	}

	xdna_hdl->ve2_mgmtctx = devm_kcalloc(dev, xdna_hdl->aie_dev_info.cols,
					     sizeof(*xdna_hdl->ve2_mgmtctx), GFP_KERNEL);
	if (!xdna_hdl->ve2_mgmtctx) {
		XDNA_ERR(xdna, "No memory for ve2_mgmtctx array");
		return -ENOMEM;
	}

	for (col = 0; col < xdna_hdl->aie_dev_info.cols; col++) {
		fw_slots = devm_kzalloc(dev, sizeof(*fw_slots), GFP_KERNEL);
		if (!fw_slots) {
			XDNA_ERR(xdna, "No memory for fw status");
			return -ENOMEM;
		}
		xdna->dev_handle->fw_slots[col] = fw_slots;
	}

	aie_np = dev->parent ? dev->parent->of_node : NULL;
	if (aie_np) {
		ret = ve2_cma_mem_region_init(xdna, aie_np);
		if (ret < 0) {
			/* CMA region init is optional; fall back to default CMA */
			XDNA_DBG(xdna, "Failed to initialize the cma memories\n");
		}

		/* Parse memory topology to enable automatic CMA region selection */
		ret = ve2_parse_mem_topology(xdna, aie_np);
		if (ret == -ENOENT)
			XDNA_DBG(xdna, "Memory topology not present; using default CMA\n");
		else if (ret < 0)
			XDNA_DBG(xdna, "Failed to parse memory topology (err=%d)\n", ret);
	}

	XDNA_DBG(xdna, "VE2 device initialized: cols=%u, rows=%u, hwctx_limit=%u",
		 xdna_hdl->aie_dev_info.cols, xdna_hdl->aie_dev_info.rows,
		 xdna_hdl->hwctx_limit);

	return 0;
}

static void ve2_fini(struct amdxdna_dev *xdna)
{
	XDNA_DBG(xdna, "VE2 device cleanup: releasing resources");

	ve2_cma_mem_region_remove(xdna);

	XDNA_DBG(xdna, "VE2 device cleanup complete");
}

const struct amdxdna_dev_ops ve2_ops = {
	.init		= ve2_init,
	.fini		= ve2_fini,
	.ctx_init	= ve2_hwctx_init,
	.ctx_fini	= ve2_hwctx_fini,
	.ctx_config     = ve2_hwctx_config,
	.cmd_submit	= ve2_cmd_submit,
	.cmd_wait	= ve2_cmd_wait,
	.get_aie_info	= ve2_get_aie_info,
	.set_aie_state	= ve2_set_aie_state,
	.get_aie_array	= ve2_get_array,
};
