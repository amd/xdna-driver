// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 */

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xlnx-ai-engine.h>

#include "amdxdna_aux_drv.h"
#include "amdxdna_ctx.h"
#include "amdxdna_solver.h"
#include "ve2_aux.h"
#include "ve2_debug.h"
#include "ve2_hwctx.h"
#include "ve2_mgmt.h"

MODULE_FIRMWARE("amdnpu/release_cert_ve2.elf");

static int ve2_store_firmware_version(struct ve2_firmware_version *c_version,
				      struct device *xaie_dev)
{
	struct ve2_firmware_version *version;
	int ret;

	version = kzalloc_obj(*version);
	if (!version)
		return -ENOMEM;

	ret = ve2_partition_read(xaie_dev, 0, 0,
				 VE2_PROG_DATA_MEMORY_OFF + VE2_CERT_VERSION_OFF,
				 VE2_CERT_VERSION_SIZE, version);
	if (ret < 0) {
		kfree(version);
		return ret;
	}

	c_version->major = version->major;
	c_version->minor = version->minor;
	strscpy(c_version->git_hash, version->git_hash, VE2_FW_HASH_STRING_LENGTH);
	strscpy(c_version->date, version->date, VE2_FW_DATE_STRING_LENGTH);
	c_version->hotfix = version->hotfix;
	c_version->build = version->build;
	kfree(version);

	return 0;
}

static int ve2_load_fw(struct amdxdna_dev_hdl *xdna_hdl)
{
	struct amdxdna_dev *xdna = xdna_hdl->xdna;
	struct aie_partition_init_args args;
	struct aie_partition_req request = { };
	const struct firmware *fw;
	struct device *xaie_dev;
	char *buf;
	int ret;

	if (!xdna_hdl->priv || !xdna_hdl->priv->fw_path)
		return -EINVAL;

	XDNA_DBG(xdna, "Loading firmware: %s", xdna_hdl->priv->fw_path);

	ret = request_firmware(&fw, xdna_hdl->priv->fw_path, xdna->ddev.dev);
	if (ret) {
		XDNA_ERR(xdna, "request fw %s failed %d", xdna_hdl->priv->fw_path, ret);
		return -ENODEV;
	}

	buf = kmalloc(fw->size, GFP_KERNEL);
	if (!buf) {
		release_firmware(fw);
		return -ENOMEM;
	}
	memcpy(buf, fw->data, fw->size);
	release_firmware(fw);

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
	args.init_opts = (AIE_PART_INIT_OPT_DEFAULT | AIE_PART_INIT_OPT_DIS_TLAST_ERROR) &
			 ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;
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
	XDNA_INFO(xdna, "CERT major: %d", xdna_hdl->fw_version.major);
	XDNA_INFO(xdna, "CERT minor: %d", xdna_hdl->fw_version.minor);

teardown:
	aie_partition_teardown(xaie_dev);
release:
	aie_partition_release(xaie_dev);
out:
	kfree(buf);
	return ret;
}

static int ve2_capture_col_firmware_status(struct amdxdna_dev *xdna,
					   struct amdxdna_mgmtctx *mgmtctx,
					   u32 lead_col, u32 col)
{
	struct amdxdna_dev_hdl *hdl = ve2_dev_hdl(xdna);
	struct ve2_firmware_status *cs;
	struct handshake *hs;
	u32 offset;
	int ret;

	if (!hdl->fw_slots || !hdl->fw_slots[lead_col + col])
		return -EINVAL;

	cs = hdl->fw_slots[lead_col + col];

	hs = kzalloc_obj(*hs);
	if (!hs)
		return -ENOMEM;

	offset = CERT_HANDSHAKE_OFF(col) + offsetof(struct handshake, mpaie_alive);
	ret = aie_partition_read_privileged_mem(mgmtctx->aie_dev, offset,
						sizeof(*hs), hs);
	if (ret < 0) {
		XDNA_ERR(xdna, "read fw status col %u failed: %d", col, ret);
		goto done;
	}

	cs->state = hs->vm.fw_state;
	cs->abs_page_index = hs->vm.abs_page_index;
	cs->ppc = hs->vm.ppc;
	cs->idle_status = hs->cert_idle_status;
	cs->misc_status = hs->misc_status;

	XDNA_DBG(xdna,
		 "FW status col %u: state=%u abs_page=%u ppc=%u idle=%u misc=%u",
		 lead_col + col, cs->state, cs->abs_page_index, cs->ppc,
		 cs->idle_status, cs->misc_status);
done:
	kfree(hs);
	return ret;
}

int ve2_get_firmware_status(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct amdxdna_mgmtctx *mgmtctx;
	int ret = 0;

	if (!vp || !vp->mgmtctx || !vp->mgmtctx->aie_dev)
		return -ENODEV;

	mgmtctx = vp->mgmtctx;

	for (u32 col = 0; col < mgmtctx->num_col; col++) {
		int r = ve2_capture_col_firmware_status(xdna, mgmtctx,
							mgmtctx->start_col, col);
		if (r < 0)
			ret = r;
	}

	return ret;
}

/*
 * ve2_clear_firmware_status - Reset the cached per-column CERT firmware status
 * for @hwctx's partition. Called at context init so a fresh context does not
 * report status left behind by a previous context that used the same columns.
 */
void ve2_clear_firmware_status(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	struct amdxdna_dev_hdl *hdl = ve2_dev_hdl(xdna);

	if (!hdl || !hdl->fw_slots)
		return;

	for (u32 col = 0; col < hwctx->num_col; col++) {
		struct ve2_firmware_status *cs = hdl->fw_slots[hwctx->start_col + col];

		if (!cs)
			continue;

		cs->state = 0;
		cs->abs_page_index = 0;
		cs->ppc = 0;
		cs->idle_status = 0;
		cs->misc_status = 0;
	}
}

static void ve2_cma_device_release(struct device *dev)
{
	kfree(dev);
}

static void ve2_cma_mem_region_remove(struct amdxdna_dev *xdna)
{
	int i;

	for (i = 0; i < MAX_MEM_REGIONS; i++) {
		struct device *dev = xdna->cma_regions[i].dev;

		if (dev) {
			of_reserved_mem_device_release(dev);
			put_device(dev);
			memset(&xdna->cma_regions[i], 0, sizeof(xdna->cma_regions[i]));
		}
	}
}

static int ve2_cma_mem_region_init(struct amdxdna_dev *xdna, struct device_node *aie_np)
{
	struct device *parent_dev = xdna->ddev.dev;
	struct reserved_mem *rmem;
	struct device_node *np;
	struct device *child_dev;
	int num_regions;
	int ret;
	int i;

	num_regions = of_count_phandle_with_args(aie_np, "memory-region", NULL);
	if (num_regions <= 0 || num_regions > MAX_MEM_REGIONS) {
		XDNA_INFO(xdna, "memory-region count=%d (expected 1..%d), skip CMA init",
			  num_regions, MAX_MEM_REGIONS);
		return -EINVAL;
	}

	for (i = 0; i < num_regions; i++) {
		child_dev = kzalloc(sizeof(*child_dev), GFP_KERNEL);
		if (!child_dev) {
			ret = -ENOMEM;
			goto cleanup;
		}

		device_initialize(child_dev);
		child_dev->parent = parent_dev;
		child_dev->of_node = aie_np;
		child_dev->coherent_dma_mask = DMA_BIT_MASK(64);
		child_dev->dma_mask = &child_dev->coherent_dma_mask;
		child_dev->release = ve2_cma_device_release;

		ret = dev_set_name(child_dev, "amdxdna-mem%d", i);
		if (ret) {
			XDNA_ERR(xdna, "Failed to set name for cma region %d", i);
			goto put_dev;
		}

		ret = of_reserved_mem_device_init_by_idx(child_dev, aie_np, i);
		if (ret) {
			XDNA_ERR(xdna, "Failed to init reserved cma region %d, ret %d", i, ret);
			goto put_dev;
		}

		/*
		 * Record the region extent so a device address can be mapped
		 * back to this index later. of_reserved_mem_device_init_by_idx()
		 * resolves the same phandle but does not hand the descriptor
		 * back. The descriptor lives in the OF core's own table and does
		 * not borrow the node's refcount, so drop the node right away.
		 */
		np = of_parse_phandle(aie_np, "memory-region", i);
		rmem = np ? of_reserved_mem_lookup(np) : NULL;
		of_node_put(np);

		xdna->cma_regions[i].dev = child_dev;
		if (rmem) {
			xdna->cma_regions[i].base = rmem->base;
			xdna->cma_regions[i].size = rmem->size;
		}

		XDNA_INFO(xdna, "CMA region %d (%s) initialized: base 0x%llx size 0x%llx",
			  i, rmem ? rmem->name : "unresolved",
			  xdna->cma_regions[i].base, xdna->cma_regions[i].size);
	}

	return 0;

put_dev:
	put_device(child_dev);
cleanup:
	ve2_cma_mem_region_remove(xdna);
	return ret;
}

static struct device_node *ve2_find_mem_topology_node(struct device_node *aie_np)
{
	struct device_node *node;

	if (!aie_np || !aie_np->parent)
		return NULL;

	for_each_child_of_node(aie_np->parent, node) {
		if (of_device_is_compatible(node, "xlnx,aie-mem-topology"))
			return node;
	}

	return NULL;
}

static int ve2_parse_mem_topology(struct amdxdna_dev *xdna, struct device_node *aie_np)
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

	topo_np = ve2_find_mem_topology_node(aie_np);
	if (!topo_np) {
		XDNA_INFO(xdna, "No aie-mem-topology node found, using default CMA");
		xdna_hdl->mem_topology.num_regions = 0;
		return -ENOENT;
	}

	for (cma_region_idx = 0; cma_region_idx < MAX_MEM_REGIONS; cma_region_idx++)
		aie_mem_nodes[cma_region_idx] = of_parse_phandle(aie_np, "memory-region",
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
				 col_range[0], col_range[1], xdna_hdl->aie_dev_info.cols - 1);
			continue;
		}

		num_phandles = of_count_phandle_with_args(region_np, "memory-region", NULL);
		if (num_phandles <= 0) {
			XDNA_DBG(xdna, "No memory-region phandles in region node");
			continue;
		}

		cma_region_bitmap = 0;
		for (phandle_idx = 0;
		     phandle_idx < num_phandles && phandle_idx < MAX_MEM_REGIONS;
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

		if (!cma_region_bitmap) {
			XDNA_DBG(xdna, "No valid CMA phandles for cols %u-%u",
				 col_range[0], col_range[1]);
			continue;
		}

		region_idx = xdna_hdl->mem_topology.num_regions;
		xdna_hdl->mem_topology.regions[region_idx].start_col = col_range[0];
		xdna_hdl->mem_topology.regions[region_idx].end_col = col_range[1];
		xdna_hdl->mem_topology.regions[region_idx].mem_bitmap = cma_region_bitmap;
		xdna_hdl->mem_topology.num_regions++;

		XDNA_INFO(xdna, "Mem topology entry %u: cols %u-%u bitmap=0x%x",
			  region_idx, col_range[0], col_range[1], cma_region_bitmap);
	}

	for (cma_region_idx = 0; cma_region_idx < MAX_MEM_REGIONS; cma_region_idx++) {
		if (aie_mem_nodes[cma_region_idx])
			of_node_put(aie_mem_nodes[cma_region_idx]);
	}
	of_node_put(topo_np);
	return 0;
}

void ve2_auto_select_mem_bitmap(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev_hdl *xdna_hdl = xdna->dev_handle;
	struct amdxdna_ctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_mem_topology *topo;
	u32 start_col;
	u32 i;

	if (!vp)
		return;

	start_col = hwctx->start_col;

	if (!xdna_hdl || !xdna_hdl->mem_topology.num_regions) {
		XDNA_DBG(xdna, "No mem topology, using default CMA (mem_bitmap=0)");
		vp->mem_bitmap = 0;
		return;
	}

	topo = &xdna_hdl->mem_topology;
	for (i = 0; i < topo->num_regions; i++) {
		if (start_col >= topo->regions[i].start_col &&
		    start_col <= topo->regions[i].end_col) {
			vp->mem_bitmap = topo->regions[i].mem_bitmap;
			XDNA_INFO(xdna, "Auto-selected mem_bitmap=0x%x for start_col=%u",
				  vp->mem_bitmap, start_col);
			return;
		}
	}

	XDNA_DBG(xdna, "No topology match for start_col=%u, using default CMA", start_col);
	vp->mem_bitmap = 0;
}

/*
 * Allocate DMA-coherent memory for a buffer that CERT dereferences itself.
 *
 * Such buffers must sit in a DDR bank the context's columns can actually
 * reach, so only the banks named by @mem_bitmap are eligible; each is tried in
 * turn and the device that served the allocation is returned in @alloc_dev for
 * the caller's later sync and free. The default CMA pool is used only when the
 * context named no bank at all, which is the case on platforms without an
 * aie-mem-topology. Falling back to it for a context that did name banks would
 * hand CERT an address it cannot route, surfacing as a NoC error at submit
 * instead of an error here.
 */
void *ve2_alloc_cert_coherent(struct amdxdna_dev *xdna, u32 mem_bitmap, size_t size,
			      dma_addr_t *dma_addr, struct device **alloc_dev)
{
	void *va = NULL;
	int i;

	*alloc_dev = NULL;

	if (mem_bitmap) {
		for (i = 0; i < MAX_MEM_REGIONS; i++) {
			struct device *dev = xdna->cma_regions[i].dev;

			if (!(mem_bitmap & (1U << i)) || !dev)
				continue;

			va = dma_alloc_coherent(dev, size, dma_addr, GFP_KERNEL);
			if (va) {
				*alloc_dev = dev;
				break;
			}
		}
	} else {
		va = dma_alloc_coherent(xdna->ddev.dev, size, dma_addr, GFP_KERNEL);
		if (va)
			*alloc_dev = xdna->ddev.dev;
	}

	if (!va)
		XDNA_ERR(xdna, "Coherent alloc failed: size=%zu mem_bitmap=0x%x", size, mem_bitmap);

	return va;
}

int ve2_probe(struct amdxdna_dev *xdna, struct amdxdna_dev_hdl *hdl)
{
	struct init_config xrs_cfg = { };
	int ret;

	ret = aie_get_device_info(&hdl->aie_dev_info);
	if (ret) {
		if (ret == -ENODEV) {
			XDNA_INFO(xdna, "AIE device not ready yet, deferring probe");
			return -EPROBE_DEFER;
		}
		XDNA_ERR(xdna, "aie_get_device_info failed %d", ret);
		return ret;
	}

	XDNA_INFO(xdna, "AIE device: %u columns, %u rows",
		  hdl->aie_dev_info.cols, hdl->aie_dev_info.rows);

	/*
	 * Determine the maximum number of hardware contexts. The ve2_hwctx_limit
	 * test module parameter overrides the per-device default when non-zero.
	 */
	if (ve2_hwctx_limit)
		hdl->hwctx_limit = ve2_hwctx_limit;
	else
		hdl->hwctx_limit = hdl->priv->hwctx_limit;
	XDNA_INFO(xdna, "Maximum limit %u hardware context(s)", hdl->hwctx_limit);

	xrs_cfg.ddev = &xdna->ddev;
	xrs_cfg.total_col = hdl->aie_dev_info.cols;

	/*
	 * Test-only override: restrict the resource-solver column window to
	 * @max_col columns (optionally offset by @start_col) instead of the full
	 * device column count. Mirrors the legacy driver's module-parameter path.
	 */
	if (max_col > 0 && start_col >= 0 &&
	    (u32)(max_col + start_col) <= hdl->aie_dev_info.cols) {
		xrs_cfg.total_col = max_col;
		XDNA_INFO(xdna, "Using module parameter: max_col=%d start_col=%d",
			  max_col, start_col);
	}

	xdna->xrs_hdl = xrsm_init(&xrs_cfg);
	if (!xdna->xrs_hdl) {
		XDNA_WARN(xdna, "Initialization of Resource resolver failed");
		return -EINVAL;
	}

	ret = ve2_mgmtctx_registry_init(hdl);
	if (ret) {
		XDNA_ERR(xdna, "mgmtctx registry init failed %d", ret);
		return ret;
	}

	/* Per-column firmware status slots, filled on hwctx teardown. */
	hdl->fw_slots = devm_kcalloc(xdna->ddev.dev, hdl->aie_dev_info.cols,
				     sizeof(*hdl->fw_slots), GFP_KERNEL);
	if (!hdl->fw_slots)
		return -ENOMEM;

	for (u32 col = 0; col < hdl->aie_dev_info.cols; col++) {
		hdl->fw_slots[col] = devm_kzalloc(xdna->ddev.dev,
						  sizeof(*hdl->fw_slots[col]),
						  GFP_KERNEL);
		if (!hdl->fw_slots[col])
			return -ENOMEM;
	}

	ret = ve2_load_fw(hdl);
	if (ret) {
		XDNA_ERR(xdna, "aie load %s failed with err %d", hdl->priv->fw_path, ret);
		return ret;
	}
	if (hdl->priv && hdl->priv->fw_path)
		XDNA_INFO(xdna, "aie fw load %s completed", hdl->priv->fw_path);
	else
		XDNA_INFO(xdna, "aie fw load completed");

	return 0;
}

static const struct amdxdna_dev_priv ve2_aux_priv = {
	.fw_path		= "amdnpu/release_cert_ve2.elf",
	.hwctx_limit		= 255,
	.ctx_limit		= 255,
};

const struct amdxdna_dev_info dev_ve2_info = {
	.device_type	= AMDXDNA_DEV_TYPE_KMQ,
	.first_col	= 0,
	.dev_priv	= &ve2_aux_priv,
	.ops		= &ve2_ops,
};

static int ve2_aux_init(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;
	struct amdxdna_dev_hdl *xdna_hdl;
	const struct amdxdna_dev_priv *priv;
	struct device_node *aie_np;
	int ret;

	priv = xdna->dev_info->dev_priv;
	if (!priv)
		return -EINVAL;

	XDNA_DBG(xdna, "Initializing VE2 device");

	xdna_hdl = devm_kzalloc(dev, sizeof(*xdna_hdl), GFP_KERNEL);
	if (!xdna_hdl)
		return -ENOMEM;

	xdna_hdl->xdna = xdna;
	xdna_hdl->priv = priv;
	xdna->dev_handle = xdna_hdl;

	ret = ve2_probe(xdna, xdna_hdl);
	if (ret)
		return ret;

	/* Initialize per-bank CMA region devices and parse memory topology from DT. */
	aie_np = dev->parent ? dev->parent->of_node : NULL;
	if (aie_np) {
		ret = ve2_cma_mem_region_init(xdna, aie_np);
		if (ret) {
			/*
			 * Bank setup is all-or-nothing, so skip the topology
			 * parse: it resolves DT phandles by index and would
			 * otherwise hand contexts a mem_bitmap naming banks
			 * that have no device behind them.
			 */
			XDNA_INFO(xdna, "CMA mem region init failed (%d), using default CMA", ret);
		} else {
			ret = ve2_parse_mem_topology(xdna, aie_np);
			if (ret == -ENOENT)
				XDNA_INFO(xdna, "No aie-mem-topology in DT, using default CMA");
			else if (ret)
				XDNA_INFO(xdna, "mem topology parse failed (%d), using default CMA",
					  ret);
		}
	} else {
		XDNA_WARN(xdna, "No parent DT node, skipping CMA region and topology init");
	}

	XDNA_INFO(xdna, "VE2 device ready (host-queue=%s)",
		  enable_polling ? "polling" : "interrupt");

	return 0;
}

static void ve2_aux_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *hdl = ve2_dev_hdl(xdna);

	if (!hdl)
		return;

	ve2_cma_mem_region_remove(xdna);
	XDNA_DBG(xdna, "VE2 device cleanup");
}

const struct amdxdna_dev_ops ve2_ops = {
	.init			= ve2_aux_init,
	.fini			= ve2_aux_fini,
	.hwctx_init		= ve2_hwctx_init,
	.hwctx_fini		= ve2_hwctx_fini,
	.hwctx_config		= ve2_hwctx_config,
	.cmd_submit		= ve2_cmd_submit,
	.cmd_wait		= ve2_cmd_wait,
	.get_aie_info		= ve2_get_aie_info,
	.get_array		= ve2_debug_get_array,
	.set_aie_state		= ve2_set_aie_state,
};
