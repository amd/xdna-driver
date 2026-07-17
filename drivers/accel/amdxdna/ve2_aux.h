/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 *
 * VE2 platform (aux): device info, probe, and DRM ops.
 * AIE partition/control is implemented in ve2_aie.c (HAL AIE-driver backend).
 */

#ifndef _VE2_AUX_H_
#define _VE2_AUX_H_

#include <linux/types.h>
#include <linux/xlnx-ai-engine.h>

#include "amdxdna_pci_drv.h"

struct amdxdna_dev_priv {
	const char			*fw_path;
	/*
	 * Max hardware/scheduling contexts. Advertised for parity with the
	 * other backends; VE2 does not yet enforce these limits (TODO).
	 */
	u32				hwctx_limit;
	u32				ctx_limit;
};

struct amdxdna_dev;

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

/* Per-column CERT firmware status snapshot, captured on hwctx teardown. */
struct ve2_firmware_status {
	u32 state;
	u32 abs_page_index;
	u32 ppc;
	u32 idle_status;
	u32 misc_status;
};

struct amdxdna_mgmtctx;
struct amdxdna_hwctx;

struct amdxdna_dev_hdl {
	struct amdxdna_dev		*xdna;
	const struct amdxdna_dev_priv	*priv;
	struct aie_device_info		aie_dev_info;
	struct ve2_firmware_version	fw_version;
	struct amdxdna_mgmtctx		*ve2_mgmtctx;
	struct ve2_firmware_status	**fw_slots;	/* [cols] per-column FW status */
};

extern const struct amdxdna_dev_ops ve2_ops;

static inline struct amdxdna_dev_hdl *ve2_dev_hdl(struct amdxdna_dev *xdna)
{
	return xdna->dev_handle;
}

int ve2_probe(struct amdxdna_dev *xdna, struct amdxdna_dev_hdl *hdl);
void ve2_auto_select_mem_bitmap(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx);

/* Capture the per-column CERT firmware status for @hwctx's partition. */
int ve2_get_firmware_status(struct amdxdna_hwctx *hwctx);

#endif /* _VE2_AUX_H_ */
