/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 */

#ifndef _VE2_AUX_H_
#define _VE2_AUX_H_

#include <linux/device.h>
#include <linux/types.h>
#include <linux/xlnx-ai-engine.h>

#include "amdxdna_drv.h"

struct amdxdna_dev_priv;

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

struct amdxdna_dev_priv {
	const char *fw_path;
};

struct amdxdna_dev;

struct amdxdna_dev_hdl {
	struct amdxdna_dev			*xdna;
	const struct amdxdna_dev_priv		*ve2_priv;
	struct ve2_firmware_version		fw_version;
	struct aie_device_info			aie_dev_info;
	struct ve2_firmware_status		**fw_slots;
};

extern const struct amdxdna_dev_info dev_ve2_info;
extern const struct amdxdna_dev_ops ve2_ops;

static inline struct amdxdna_dev_hdl *ve2_dev_hdl(struct amdxdna_dev *xdna)
{
	return xdna->dev_handle;
}

#endif /* _VE2_AUX_H_ */
