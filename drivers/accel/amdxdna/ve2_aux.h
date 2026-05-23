/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 *
 * VE2 platform (aux): device info, probe, memory topology, and DRM ops.
 * AIE partition/control is implemented in ve2_aie.c (HAL AIE-driver backend).
 */

#ifndef _VE2_AUX_H_
#define _VE2_AUX_H_

#include <linux/types.h>
#include <linux/xlnx-ai-engine.h>

#include "amdxdna_drv.h"

enum ve2_fw_interface {
	VE2_FW_INTERFACE_AIE = 0,
	VE2_FW_INTERFACE_MAILBOX,
};

struct amdxdna_dev_priv {
	const char			*fw_path;
	enum ve2_fw_interface	fw_interface;
};

struct amdxdna_dev;

struct ve2_aie_mgmtctx;

/* Certificate image layout (AIE program data memory) */
#define VE2_PROG_DATA_MEMORY_OFF	0x80000
#define VE2_CERT_VERSION_OFF		0x50
#define VE2_CERT_VERSION_SIZE		0x40
#define VE2_FW_HASH_STRING_LENGTH	41
#define VE2_FW_DATE_STRING_LENGTH	11

struct ve2_firmware_version {
	u8 major;
	u8 minor;
	char git_hash[VE2_FW_HASH_STRING_LENGTH];
	char date[VE2_FW_DATE_STRING_LENGTH];
	u8 hotfix;
	u8 build;
};

struct ve2_firmware_status {
	u32 state;
	u32 abs_page_index;
	u32 ppc;
	u32 idle_status;
	u32 misc_status;
};

struct ve2_mem_region {
	u32	start_col;
	u32	end_col;
	u32	mem_bitmap;
};

struct ve2_mem_topology {
	u32			num_regions;
	struct ve2_mem_region	regions[AMDXDNA_MAX_MEM_REGIONS];
};

struct amdxdna_dev_hdl {
	struct amdxdna_dev		*xdna;
	const struct amdxdna_dev_priv	*priv;
	struct aie_device_info		aie_dev_info;
	struct ve2_firmware_version	fw_version;
	struct ve2_firmware_status	**fw_slots;
	enum ve2_fw_interface		fw_interface;
	struct ve2_aie_mgmtctx		**hal_mgmt_slot;
	struct ve2_mem_topology		mem_topology;
};

extern const struct amdxdna_dev_ops ve2_ops;

static inline struct amdxdna_dev_hdl *ve2_dev_hdl(struct amdxdna_dev *xdna)
{
	return xdna->dev_handle;
}

int ve2_probe(struct amdxdna_dev *xdna, struct amdxdna_dev_hdl *hdl);
void ve2_cma_mem_region_remove(struct amdxdna_dev *xdna);
struct device *ve2_dma_dev(struct amdxdna_dev *xdna, u32 mem_bitmap);
void ve2_auto_select_mem_bitmap(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx);

const char *ve2_fw_interface_name(enum ve2_fw_interface iface);

#endif /* _VE2_AUX_H_ */
