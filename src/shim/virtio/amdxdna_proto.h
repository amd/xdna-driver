/*
 * Copyright 2025 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: MIT
 */

#ifndef AMDXDNA_PROTO_H_
#define AMDXDNA_PROTO_H_

#include "drm_hw.h"

enum amdxdna_ccmd {
	AMDXDNA_CCMD_NOP = 1,
	AMDXDNA_CCMD_INIT,
	AMDXDNA_CCMD_CREATE_BO,
	AMDXDNA_CCMD_DESTROY_BO,
	AMDXDNA_CCMD_CREATE_CTX,
	AMDXDNA_CCMD_DESTROY_CTX,
	AMDXDNA_CCMD_CONFIG_CTX,
	AMDXDNA_CCMD_EXEC_CMD,
};

#ifdef __cplusplus
#define AMDXDNA_CCMD(_cmd, _len) {		\
	.cmd = AMDXDNA_CCMD_##_cmd,		\
	.len = (_len),				\
}
#else
#define AMDXDNA_CCMD(_cmd, _len) (struct vdrm_ccmd_req){	\
	.cmd = MSM_CCMD_##_cmd,					\
	.len = (_len),						\
}
#endif

struct amdxdna_ccmd_rsp {
	struct vdrm_ccmd_rsp base;
	int32_t ret;
};
static_assert(sizeof(struct amdxdna_ccmd_rsp) == 8, "bug");

/*
 * AMDXDNA_CCMD_NOP
 */
struct amdxdna_ccmd_nop_req {
	struct vdrm_ccmd_req hdr;
};

/*
 * AMDXDNA_CCMD_INIT
 */
struct amdxdna_ccmd_init_req {
	struct vdrm_ccmd_req hdr;
	uint32_t rsp_res_id;
	uint32_t _pad;
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_init_req)

/*
 * AMDXDNA_CCMD_CREATE_BO
 */

struct amdxdna_ccmd_create_bo_req {
	struct vdrm_ccmd_req hdr;
	uint32_t res_id;
	uint32_t bo_type;
	uint64_t size;
	uint64_t map_align;
	uint32_t _pad;
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_create_bo_req)

struct amdxdna_ccmd_create_bo_rsp {
	struct amdxdna_ccmd_rsp hdr;
	uint64_t xdna_addr;
	uint32_t handle;
};

/*
 * AMDXDNA_CCMD_DESTROY_BO
 */
struct amdxdna_ccmd_destroy_bo_req {
	struct vdrm_ccmd_req hdr;
	uint32_t handle;
	uint32_t _pad;
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_destroy_bo_req)

/*
 * AMDXDNA_CCMD_CREATE_CTX
 */
struct amdxdna_ccmd_create_ctx_req {
	struct vdrm_ccmd_req hdr;
	struct amdxdna_qos_info qos_info;
	uint32_t umq_blob_id;
	uint32_t log_buf_blob_id;
	uint32_t max_opc;
	uint32_t num_tiles;
	uint32_t mem_size;
	uint32_t _pad;
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_create_ctx_req)

struct amdxdna_ccmd_create_ctx_rsp {
	struct amdxdna_ccmd_rsp hdr;
	uint32_t handle;
};

/*
 * AMDXDNA_CCMD_DESTROY_CTX
 */
struct amdxdna_ccmd_destroy_ctx_req {
	struct vdrm_ccmd_req hdr;
	uint32_t handle;
	uint32_t _pad;
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_destroy_ctx_req)

/*
 * AMDXDNA_CCMD_CONFIG_CTX
 */
struct amdxdna_ccmd_config_ctx_req {
	struct vdrm_ccmd_req hdr;
	uint32_t handle;
	uint32_t _pad;
	uint32_t param_type;
	uint32_t param_val_size;
	uint64_t param_val[];
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_config_ctx_req)

/*
 * AMDXDNA_CCMD_EXEC_CMD
 */
struct amdxdna_ccmd_exec_cmd_req {
	struct vdrm_ccmd_req hdr;
	uint32_t ctx_handle;
	uint32_t type;
	uint32_t cmd_count;
	uint32_t arg_count;
	uint64_t cmds_n_args[];
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_exec_cmd_req)

struct amdxdna_ccmd_exec_cmd_rsp {
	struct amdxdna_ccmd_rsp hdr;
	uint64_t seq;
};

#endif /* AMDXDNA_PROTO_H_ */
