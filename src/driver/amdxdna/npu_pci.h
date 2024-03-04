/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#ifndef _NPU_PCI_H_
#define _NPU_PCI_H_

#include "amdxdna_drv.h"
#include "npu_common.h"

#include <drm/drm_accel.h>

struct npu_device;
int npu_init(struct amdxdna_dev *xdna);
void npu_fini(struct amdxdna_dev *xdna);
int npu_hw_start(struct npu_device *ndev);
void npu_hw_stop(struct npu_device *ndev);
int npu_alloc_resource(struct amdxdna_hwctx *hwctx);
int npu_release_resource(struct amdxdna_hwctx *hwctx);

void npu_debugfs_add(struct npu_device *ndev);

int npu_suspend_fw(struct npu_device *ndev);
int npu_resume_fw(struct npu_device *ndev);
int npu_check_protocol_version(struct npu_device *ndev);
int npu_assign_mgmt_pasid(struct npu_device *ndev, u16 pasid);
int npu_query_version(struct npu_device *ndev, struct aie_version *version);
int npu_query_metadata(struct npu_device *ndev, struct aie_metadata *metadata);
int npu_query_firmware_version(struct npu_device *ndev,
			       struct amdxdna_fw_ver *fw_ver);
int npu_register_pdis(struct npu_device *ndev, struct amdxdna_xclbin *xclbin);
int npu_unregister_pdis(struct npu_device *ndev, struct amdxdna_xclbin *xclbin);
int npu_create_context(struct npu_device *ndev, struct amdxdna_hwctx *hwctx);
int npu_destroy_context(struct npu_device *ndev, struct amdxdna_hwctx *hwctx);
int npu_map_host_buf(struct npu_device *ndev, u32 context_id, u64 addr, u64 size);
int npu_query_error(struct npu_device *ndev, u64 addr, u32 size, u32 *row,
		    u32 *col, u32 *mod, u32 *count, bool *next);
int npu_query_status(struct npu_device *ndev, u32 start_col, u32 num_col,
		     char *buf, u32 size, u32 *cols_filled);
int npu_query_power_sensor(struct npu_device *ndev, struct amdxdna_drm_query_sensor *args);

int npu_config_cu(struct npu_device *ndev, struct mailbox_channel *chann,
		  struct amdxdna_xclbin *xclbin);
int npu_execbuf(struct npu_device *ndev, struct mailbox_channel *chann,
		u32 cu_idx, u32 *payload, u32 payload_len, void *handle,
		void (*notify_cb)(void *, const u32 *, size_t));
void npu_get_aie_metadata(struct amdxdna_dev *xdna, struct amdxdna_drm_query_aie_metadata *args);
int npu_get_aie_status(struct amdxdna_dev *xdna, struct amdxdna_drm_query_aie_status *args);
void npu_get_aie_version(struct amdxdna_dev *xdna, struct amdxdna_drm_query_aie_version *args);
void npu_get_clock_metadata(struct amdxdna_dev *xdna,
			    struct amdxdna_drm_query_clock_metadata *args);

#if defined(CONFIG_DEBUG_FS)
int npu_self_test(struct npu_device *ndev);
#endif /* CONFIG_DEBUG_FS */

#endif /* _NPU_PCI_H_ */
