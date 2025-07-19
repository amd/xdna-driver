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
    AMDXDNA_CCMD_WAIT_CMD,
    AMDXDNA_CCMD_GET_LAST_SEQ,
    AMDXDNA_CCMD_ADD_SYNCOBJ,
    AMDXDNA_CCMD_SIG_SYNCOBJ,
    AMDXDNA_CCMD_GET_INFO,
    AMDXDNA_CCMD_READ_SYSFS,
};

#ifdef __cplusplus
#define AMDXDNA_CCMD(_cmd, _len) {          \
    .cmd = AMDXDNA_CCMD_##_cmd,             \
    .len = (_len),                          \
}
#else
#define AMDXDNA_CCMD(_cmd, _len) (struct vdrm_ccmd_req){    \
    .cmd = MSM_CCMD_##_cmd,                                 \
    .len = (_len),                                          \
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
    uint32_t syncobj_hdl;
};

/*
 * AMDXDNA_CCMD_DESTROY_CTX
 */
struct amdxdna_ccmd_destroy_ctx_req {
    struct vdrm_ccmd_req hdr;
    uint32_t handle;
    uint32_t syncobj_hdl;
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
    uint32_t arg_offset; /* number of dwords from the cmds_n_args[0] */
    uint32_t cmds_n_args[];
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_exec_cmd_req)

struct amdxdna_ccmd_exec_cmd_rsp {
    struct amdxdna_ccmd_rsp hdr;
    uint64_t seq;
};

/*
 * AMDXDNA_CCMD_WAIT_CMD
 */
struct amdxdna_ccmd_wait_cmd_req {
    struct vdrm_ccmd_req hdr;
    uint64_t seq;
    uint32_t syncobj_hdl;
    uint32_t _pad;
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_wait_cmd_req)

/*
 * AMDXDNA_CCMD_get_last_seq_req
 */
struct amdxdna_ccmd_get_last_seq_req {
    struct vdrm_ccmd_req hdr;
    uint32_t syncobj_hdl;
    uint32_t _pad;
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_get_last_seq_req)

struct amdxdna_ccmd_get_last_seq_rsp {
    struct amdxdna_ccmd_rsp hdr;
    uint64_t seq;
};

/*
 * AMDXDNA_CCMD_ADD_SYNCOBJ
 */
struct amdxdna_ccmd_add_syncobj_req {
    struct vdrm_ccmd_req hdr;
    uint32_t ctx_handle;
    uint32_t _pad;
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_add_syncobj_req)

struct amdxdna_ccmd_add_syncobj_rsp {
    struct amdxdna_ccmd_rsp hdr;
    uint32_t syncobj_hdl;
};

/*
 * AMDXDNA_CCMD_SIG_SYNCOBJ
 */
struct amdxdna_ccmd_sig_syncobj_req {
    struct vdrm_ccmd_req hdr;
    uint32_t syncobj_hdl;
    uint32_t _pad;
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_sig_syncobj_req)

/*
 * AMDXDNA_CCMD_GET_INFO
 */
struct amdxdna_ccmd_get_info_req {
    struct vdrm_ccmd_req hdr;
    uint32_t param;
    uint32_t size;
    uint32_t num_element; /* non-zero means get info array */
    uint32_t info_res;
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_get_info_req)

struct amdxdna_ccmd_get_info_rsp {
    struct amdxdna_ccmd_rsp hdr;
    uint32_t size;
    uint32_t num_element;
};

/*
 * AMDXDNA_CCMD_READ_SYSFS
 */
struct amdxdna_ccmd_read_sysfs_req {
    struct vdrm_ccmd_req hdr;
    char node_name[];
};
DEFINE_CAST(vdrm_ccmd_req, amdxdna_ccmd_read_sysfs_req)

struct amdxdna_ccmd_read_sysfs_rsp {
    struct amdxdna_ccmd_rsp hdr;
    int32_t val_len;
    char val[];
};

#endif /* AMDXDNA_PROTO_H_ */
