// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef AMDXDNA_PROTO_H_
#define AMDXDNA_PROTO_H_

#include "drm_hw.h"

enum amdxdna_ccmd {
	AMDXDNA_CCMD_NOP = 1,
	AMDXDNA_CCMD_INIT,
	AMDXDNA_CCMD_MAP_BO,
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
 * AMDXDNA_CCMD_MAP_BO
 */

struct amdxdna_ccmd_map_bo_req {
	struct vdrm_ccmd_req hdr;
	uint32_t res_id;
	uint32_t alignment;
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_map_bo_req)

struct amdxdna_ccmd_map_bo_rsp {
	struct amdxdna_ccmd_rsp hdr;
	uint64_t iov_addr;
};


#endif /* AMDXDNA_PROTO_H_ */
