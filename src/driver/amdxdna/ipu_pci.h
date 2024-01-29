/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 * All Rights Reserved.
 *
 * Authors:
 *	Min Ma <min.ma@amd.com>
 */

#ifndef _IPU_PCI_H_
#define _IPU_PCI_H_

#include "amdxdna_drv.h"
#include "ipu_common.h"

#include <drm/drm_accel.h>

struct ipu_device;
int ipu_init(struct amdxdna_dev *xdna);
void ipu_fini(struct amdxdna_dev *xdna);
int ipu_alloc_resource(struct amdxdna_hwctx *hwctx);
int ipu_release_resource(struct amdxdna_hwctx *hwctx);

int ipu_sysfs_init(struct ipu_device *idev);
void ipu_sysfs_fini(struct ipu_device *idev);
void ipu_debugfs_add(struct ipu_device *idev);

int ipu_suspend_fw(struct ipu_device *idev);
int ipu_resume_fw(struct ipu_device *idev);
int ipu_check_header_hash(struct ipu_device *idev);
int ipu_assign_mgmt_pasid(struct ipu_device *idev, u16 pasid);
int ipu_register_pdis(struct ipu_device *idev, struct amdxdna_xclbin *cache);
int ipu_unregister_pdis(struct ipu_device *idev, struct amdxdna_xclbin *cache);
int ipu_create_context(struct ipu_device *idev, struct amdxdna_hwctx *hwctx);
int ipu_destroy_context(struct ipu_device *idev, struct amdxdna_hwctx *hwctx);
int ipu_map_host_buf(struct ipu_device *idev, u32 context_id, u64 addr, u64 size);
int ipu_query_error(struct ipu_device *idev, u64 addr, u32 size, u32 *row,
		    u32 *col, u32 *mod, u32 *count, bool *next);
int ipu_query_version(struct ipu_device *idev, struct aie_version *version);
int ipu_query_metadata(struct ipu_device *idev, struct aie_metadata *metadata);
int ipu_query_status(struct ipu_device *idev, u32 start_col, u32 num_col,
		     char *buf, u32 size, u32 *cols_filled);

int ipu_config_cu(struct ipu_device *idev, struct mailbox_channel *chann,
		  struct amdxdna_xclbin *xclbin);
int ipu_execbuf(struct ipu_device *idev, struct mailbox_channel *chann,
		u32 cu_idx, u32 *payload, void *handle,
		void (*notify_cb)(void *, const u32 *, size_t));
int ipu_get_aie_status(struct amdxdna_dev *xdna, struct amdxdna_drm_query_aie_status *args);

#if defined(CONFIG_DEBUG_FS)
int ipu_self_test(struct ipu_device *idev);
#endif /* CONFIG_DEBUG_FS */

#endif /* _IPU_PCI_H_ */
