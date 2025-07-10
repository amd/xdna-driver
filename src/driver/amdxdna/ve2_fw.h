/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _VE2_FW_H_
#define _VE2_FW_H_

#define VE2_CERT_VERSION_OFF	0x50
#define VE2_CERT_VERSION_SIZE	0x40

#define VE2_FW_HASH_STRING_LENGTH	41
#define VE2_FW_DATE_STRING_LENGTH	11

struct amdxdna_dev_hdl;
struct amdxdna_ctx;

struct ve2_firmware_version {
	u8 major;
	u8 minor;
	char git_hash[VE2_FW_HASH_STRING_LENGTH];
	char date[VE2_FW_DATE_STRING_LENGTH];
};

struct ve2_firmware_status {
	u32 state;
	u32 abs_page_index;
	u32 ppc;
	u32 idle_status;
	u32 misc_status;
};

int ve2_store_firmware_version(struct amdxdna_dev_hdl *xdna_hdl, struct device *xaie_dev);
int ve2_get_firmware_status(struct amdxdna_ctx *hwctx);

#endif /* _VE2_FW_H_ */
