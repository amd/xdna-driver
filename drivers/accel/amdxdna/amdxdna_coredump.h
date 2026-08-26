/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */
#ifndef _AMDXDNA_COREDUMP_H_
#define _AMDXDNA_COREDUMP_H_

#include <linux/types.h>

struct aie_device;
struct amdxdna_client;
struct amdxdna_hwctx;
struct amdxdna_drm_get_array;
struct amdxdna_drm_get_info;
struct amdxdna_drm_set_state;

/*
 * struct amdxdna_coredump_buf_entry - __packed to match firmware buffer_list
 */
struct amdxdna_coredump_buf_entry {
	u64				buf_addr;
	u32				buf_size;
	u32				reserved;
} __packed;

int amdxdna_get_coredump(struct aie_device *aie,
			 struct amdxdna_client *client,
			 struct amdxdna_drm_get_array *args);
char *amdxdna_get_hwctx_coredump(struct aie_device *aie,
				 struct amdxdna_hwctx *hwctx);
int amdxdna_get_auto_coredump_mode(struct amdxdna_client *client,
				   struct amdxdna_drm_get_info *args);
int amdxdna_set_auto_coredump_mode(struct amdxdna_client *client,
				   struct amdxdna_drm_set_state *args);

#endif /* _AMDXDNA_COREDUMP_H_ */
