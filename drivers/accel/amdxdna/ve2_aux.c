// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2 platform driver: aux attach, device probe (cert, topology, XRS), DRM ops.
 * HAL AIE-driver backend and xilinx-aie access live in ve2_aie.c.
 */

#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/xlnx-ai-engine.h>

#include "amdxdna_aux_drv.h"
#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "ve2_aux.h"
#include "ve2_debug.h"
#include "ve2_hq.h"
#include "ve2_hwctx.h"
#include "ve2_trace.h"
#include "amdxdna_ve2_solver.h"

MODULE_FIRMWARE("amdnpu/release_cert_ve2.elf");

static int ve2_partition_read_fw(struct device *aie_dev, u32 col, u32 row,
				 u32 offset, size_t size, void *buf)
{
	struct aie_location loc = { .col = col, .row = row };

	return aie_partition_read(aie_dev, loc, offset, size, buf);
}

static int ve2_store_firmware_version(struct ve2_firmware_version *c_version,
				      struct device *xaie_dev)
{
	struct ve2_firmware_version *version;
	int ret;

	version = kzalloc(sizeof(*version), GFP_KERNEL);
	if (!version)
		return -ENOMEM;

	ret = ve2_partition_read_fw(xaie_dev, 0, 0,
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

static int ve2_partition_init_fw(struct device *dev, struct aie_partition_init_args *args)
{
	return aie_partition_initialize(dev, args);
}

static int ve2_load_cert_firmware(struct amdxdna_dev_hdl *xdna_hdl)
{
	struct amdxdna_dev *xdna = xdna_hdl->xdna;
	struct aie_partition_init_args args;
	struct aie_partition_req request;
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
	ret = ve2_partition_init_fw(xaie_dev, &args);
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

static int ve2_init_fw_status_slots(struct amdxdna_dev *xdna, struct amdxdna_dev_hdl *hdl)
{
	struct device *dev = xdna->ddev.dev;
	struct ve2_firmware_status *sl;
	u32 col;

	if (!hdl->aie_dev_info.cols)
		return 0;

	hdl->fw_slots = devm_kcalloc(dev, hdl->aie_dev_info.cols, sizeof(*hdl->fw_slots),
				     GFP_KERNEL);
	if (!hdl->fw_slots) {
		XDNA_ERR(xdna, "No memory for fw_slots array");
		return -ENOMEM;
	}

	for (col = 0; col < hdl->aie_dev_info.cols; col++) {
		sl = devm_kzalloc(dev, sizeof(*sl), GFP_KERNEL);
		if (!sl) {
			XDNA_ERR(xdna, "No memory for fw status");
			return -ENOMEM;
		}
		hdl->fw_slots[col] = sl;
	}

	return 0;
}

static void ve2_cma_device_release(struct device *dev)
{
	kfree(dev);
}

void ve2_cma_mem_region_remove(struct amdxdna_dev *xdna)
{
	int i;

	for (i = 0; i < AMDXDNA_MAX_MEM_REGIONS; i++) {
		struct device *dev = xdna->cma_region_devs[i];

		if (dev) {
			of_reserved_mem_device_release(dev);
			put_device(dev);
			xdna->cma_region_devs[i] = NULL;
		}
	}
}

static int ve2_cma_mem_region_init(struct amdxdna_dev *xdna, struct device_node *aie_np)
{
	struct device *parent_dev = xdna->ddev.dev;
	struct device *child_dev;
	int num_regions;
	int ret;
	int i;

	num_regions = of_count_phandle_with_args(aie_np, "memory-region", NULL);
	if (num_regions <= 0 || num_regions > AMDXDNA_MAX_MEM_REGIONS)
		return -EINVAL;

	for (i = 0; i < num_regions; i++) {
		child_dev = kzalloc(sizeof(*child_dev), GFP_KERNEL);
		if (!child_dev) {
			XDNA_ERR(xdna, "Failed to alloc child_dev for cma region %d", i);
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
			XDNA_ERR(xdna, "Failed to init reserved cma region %d", i);
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
	struct amdxdna_dev_hdl *hdl = xdna->dev_handle;
	struct device_node *aie_mem_nodes[AMDXDNA_MAX_MEM_REGIONS];
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
		XDNA_INFO(xdna, "No aie_mem_topology node found, using default CMA");
		hdl->mem_topology.num_regions = 0;
		return -ENOENT;
	}

	for (cma_region_idx = 0; cma_region_idx < AMDXDNA_MAX_MEM_REGIONS; cma_region_idx++)
		aie_mem_nodes[cma_region_idx] = of_parse_phandle(aie_np, "memory-region",
								 cma_region_idx);

	hdl->mem_topology.num_regions = 0;

	for_each_child_of_node(topo_np, region_np) {
		if (hdl->mem_topology.num_regions >= AMDXDNA_MAX_MEM_REGIONS) {
			XDNA_DBG(xdna, "Too many topology entries, max %d",
				 AMDXDNA_MAX_MEM_REGIONS);
			break;
		}

		ret = of_property_read_u32_array(region_np, "columns", col_range, 2);
		if (ret) {
			XDNA_DBG(xdna, "Failed to read columns property: %d", ret);
			continue;
		}

		if (col_range[0] > col_range[1] ||
		    col_range[1] >= hdl->aie_dev_info.cols) {
			XDNA_DBG(xdna, "Columns range %u-%u out of bounds (valid 0..%u)",
				 col_range[0], col_range[1],
				 hdl->aie_dev_info.cols - 1);
			continue;
		}

		num_phandles = of_count_phandle_with_args(region_np, "memory-region", NULL);
		if (num_phandles <= 0) {
			XDNA_DBG(xdna, "No memory-region phandles in region node");
			continue;
		}

		cma_region_bitmap = 0;
		for (phandle_idx = 0;
		     phandle_idx < (u32)num_phandles && phandle_idx < AMDXDNA_MAX_MEM_REGIONS;
		     phandle_idx++) {
			mem_region_np = of_parse_phandle(region_np, "memory-region", phandle_idx);
			if (!mem_region_np)
				continue;
			for (cma_region_idx = 0; cma_region_idx < AMDXDNA_MAX_MEM_REGIONS;
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

		region_idx = hdl->mem_topology.num_regions;
		hdl->mem_topology.regions[region_idx].start_col = col_range[0];
		hdl->mem_topology.regions[region_idx].end_col = col_range[1];
		hdl->mem_topology.regions[region_idx].mem_bitmap = cma_region_bitmap;
		hdl->mem_topology.num_regions++;

		XDNA_DBG(xdna, "Mem topology entry %u: cols %u-%u bitmap=0x%x",
			 region_idx, col_range[0], col_range[1], cma_region_bitmap);
	}

	for (cma_region_idx = 0; cma_region_idx < AMDXDNA_MAX_MEM_REGIONS; cma_region_idx++) {
		if (aie_mem_nodes[cma_region_idx])
			of_node_put(aie_mem_nodes[cma_region_idx]);
	}
	of_node_put(topo_np);
	return 0;
}

struct device *ve2_dma_dev(struct amdxdna_dev *xdna, u32 mem_bitmap)
{
	unsigned int r;

	for (r = 0; r < AMDXDNA_MAX_MEM_REGIONS; r++) {
		if ((mem_bitmap & (1U << r)) && xdna->cma_region_devs[r])
			return xdna->cma_region_devs[r];
	}

	return xdna->ddev.dev;
}

void ve2_auto_select_mem_bitmap(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev_hdl *hdl = ve2_dev_hdl(xdna);
	struct ve2_hwctx_link *link = hwctx->aux_ctx_priv;
	struct ve2_hwctx_priv *vp = ve2_hw_priv(hwctx);
	struct ve2_mem_topology *topo;
	u32 start_col = hwctx->start_col;
	u32 region_idx;
	u32 bitmap = 0;

	if (!hdl || !link) {
		if (link)
			link->mem_bitmap = 0;
		if (vp)
			vp->mem_bitmap = 0;
		return;
	}

	topo = &hdl->mem_topology;
	for (region_idx = 0; region_idx < topo->num_regions; region_idx++) {
		if (start_col >= topo->regions[region_idx].start_col &&
		    start_col <= topo->regions[region_idx].end_col) {
			bitmap = topo->regions[region_idx].mem_bitmap;
			XDNA_DBG(xdna, "Auto-selected mem_bitmap=0x%x for start_col=%u",
				 bitmap, start_col);
			link->mem_bitmap = bitmap;
			if (vp)
				vp->mem_bitmap = bitmap;
			return;
		}
	}

	/* XRT shim uses bank bitmap in CREATE_BO flags low 8 bits; default region 0. */
	XDNA_DBG(xdna, "No topology match for start_col=%u, using default mem_bitmap=0x1",
		 start_col);
	link->mem_bitmap = 0x1;
	if (vp)
		vp->mem_bitmap = 0x1;
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

	xrs_cfg.ddev = &xdna->ddev;
	xrs_cfg.total_col = hdl->aie_dev_info.cols;
	xdna->xrs_hdl = ve2_xrsm_init(&xrs_cfg);
	if (!xdna->xrs_hdl) {
		XDNA_WARN(xdna, "Initialization of Resource resolver failed");
		return -EINVAL;
	}

	ret = ve2_load_cert_firmware(hdl);
	if (ret) {
		XDNA_ERR(xdna, "aie load %s failed with err %d", hdl->priv->fw_path, ret);
		return ret;
	}
	if (hdl->priv && hdl->priv->fw_path)
		XDNA_INFO(xdna, "aie fw load %s completed", hdl->priv->fw_path);
	else
		XDNA_INFO(xdna, "aie fw load completed");

	ret = ve2_init_fw_status_slots(xdna, hdl);
	if (ret)
		return ret;

	if (hdl->aie_dev_info.cols) {
		hdl->hal_mgmt_slot = devm_kcalloc(xdna->ddev.dev, hdl->aie_dev_info.cols,
						  sizeof(*hdl->hal_mgmt_slot), GFP_KERNEL);
		if (!hdl->hal_mgmt_slot)
			return -ENOMEM;
	}

	{
		struct device *dev = xdna->ddev.dev;
		struct device_node *aie_np = dev->parent ? dev->parent->of_node : NULL;

		if (!aie_np)
			return 0;

		ret = ve2_cma_mem_region_init(xdna, aie_np);
		if (ret < 0)
			XDNA_INFO(xdna, "CMA region init failed (%d), using default DMA", ret);

		ret = ve2_parse_mem_topology(xdna, aie_np);
		if (ret == -ENOENT)
			XDNA_INFO(xdna, "Memory topology not present; using default CMA");
		else if (ret < 0)
			XDNA_INFO(xdna, "Failed to parse memory topology (%d)", ret);
	}

	return 0;
}

const char *ve2_fw_interface_name(enum ve2_fw_interface iface)
{
	switch (iface) {
	case VE2_FW_INTERFACE_AIE:
		return "aie";
	case VE2_FW_INTERFACE_MAILBOX:
		return "mbox";
	default:
		return "unknown";
	}
}

static const struct amdxdna_dev_priv ve2_aux_priv_aie = {
	.fw_path		= "amdnpu/release_cert_ve2.elf",
	.fw_interface		= VE2_FW_INTERFACE_AIE,
};

const struct amdxdna_dev_info dev_ve2_info_aie = {
	.device_type	= AMDXDNA_DEV_TYPE_KMQ,
	.first_col	= 0,
	.dev_priv	= &ve2_aux_priv_aie,
	.ops		= &ve2_ops,
};

static int ve2_init(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;
	struct amdxdna_dev_hdl *xdna_hdl;
	const struct amdxdna_dev_priv *priv;
	enum ve2_fw_interface fw_iface;
	int ret;

	priv = xdna->dev_info->dev_priv;
	if (!priv)
		return -EINVAL;

	fw_iface = priv->fw_interface;
	XDNA_DBG(xdna, "Initializing VE2 device (fw_interface=%s)",
		 ve2_fw_interface_name(fw_iface));

	if (fw_iface != VE2_FW_INTERFACE_AIE) {
		XDNA_ERR(xdna, "Unsupported VE2 fw_interface %s",
			 ve2_fw_interface_name(fw_iface));
		return -ENODEV;
	}

	xdna_hdl = devm_kzalloc(dev, sizeof(*xdna_hdl), GFP_KERNEL);
	if (!xdna_hdl)
		return -ENOMEM;

	xdna_hdl->xdna = xdna;
	xdna_hdl->priv = priv;
	xdna_hdl->fw_interface = fw_iface;
	xdna->dev_handle = xdna_hdl;

	ret = ve2_probe(xdna, xdna_hdl);
	if (ret)
		return ret;

	XDNA_INFO(xdna, "VE2 device ready (fw_interface=%s, host-queue=%s)",
		  ve2_fw_interface_name(fw_iface),
		  enable_polling ? "polling" : "interrupt");

	return 0;
}

static void ve2_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *hdl = ve2_dev_hdl(xdna);

	if (!hdl)
		return;

	XDNA_DBG(xdna, "VE2 device cleanup");

	ve2_cma_mem_region_remove(xdna);
}

static int ve2_get_aie_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	return ve2_debug_get_aie_info(client, args);
}

static int ve2_set_aie_state(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	return ve2_debug_set_aie_state(client, args);
}

static int ve2_hwctx_init(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	VE2_TRACE(xdna, "hwctx_init ioctl path pid=%d", hwctx->client->pid);
	return ve2_hwctx_setup(hwctx);
}

static void ve2_hwctx_fini(struct amdxdna_hwctx *hwctx)
{
	ve2_hwctx_teardown(hwctx);
}

static int ve2_hwctx_config(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 op_timeout;

	(void)buf;
	(void)size;

	switch (type) {
	case DRM_AMDXDNA_HWCTX_CONFIG_OPCODE_TIMEOUT:
		if (copy_from_user(&op_timeout, u64_to_user_ptr(value), sizeof(op_timeout))) {
			XDNA_ERR(xdna, "Failed to copy opcode timeout from user");
			return -EFAULT;
		}
		return ve2_hwctx_config_opcode_timeout(hwctx, op_timeout);
	default:
		XDNA_DBG(xdna, "Not supported type %u", type);
		return -EOPNOTSUPP;
	}
}

static int ve2_hwctx_sync_debug_bo(struct amdxdna_hwctx *hwctx, u32 debug_bo_hdl)
{
	(void)hwctx;
	(void)debug_bo_hdl;

	return 0;
}

static void ve2_hmm_invalidate(struct amdxdna_gem_obj *abo, unsigned long cur_seq)
{
}

static int ve2_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq)
{
	return ve2_hq_cmd_submit(hwctx, job, seq);
}

static int ve2_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout_ms)
{
	VE2_TRACE(hwctx->client->xdna, "cmd_wait ioctl path pid=%d seq=%llu to=%u",
		  hwctx->client->pid, seq, timeout_ms);
	return ve2_hq_cmd_wait(hwctx, seq, timeout_ms);
}

static int ve2_get_array(struct amdxdna_client *client, struct amdxdna_drm_get_array *args)
{
	return ve2_debug_get_array(client, args);
}

const struct amdxdna_dev_ops ve2_ops = {
	.init			= ve2_init,
	.fini			= ve2_fini,
	.hwctx_init		= ve2_hwctx_init,
	.hwctx_fini		= ve2_hwctx_fini,
	.hwctx_config		= ve2_hwctx_config,
	.cmd_submit		= ve2_cmd_submit,
	.cmd_wait		= ve2_cmd_wait,
	.get_aie_info		= ve2_get_aie_info,
	.set_aie_state		= ve2_set_aie_state,
	.get_array		= ve2_get_array,
	.hwctx_sync_debug_bo	= ve2_hwctx_sync_debug_bo,
	.hmm_invalidate		= ve2_hmm_invalidate,
};
