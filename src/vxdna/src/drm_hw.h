// SPDX-License-Identifier: MIT
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.
// Copyright 2022 Google LLC

#ifndef DRM_HW_H_
#define DRM_HW_H_

#ifdef ENABLE_DRM_AMDGPU
#include <amdgpu.h>
#endif

/**
 * When adding new caps to the end of the capset struct, a value of
 * zero should be the fallback.  Ie. a newer guest on an older host
 * will see a zero value.
 *
 * For boolean caps, use 1/~0 for true/false
 */
#define VIRTGPU_CAP_BOOL_UNSUPPORTED_BY_HOST  0
#define VIRTGPU_CAP_BOOL_FALSE               ~0
#define VIRTGPU_CAP_BOOL_TRUE                 1


struct vaccel_drm_capset {
   uint32_t wire_format_version;
   /* Underlying drm device version: */
   uint32_t version_major;
   uint32_t version_minor;
   uint32_t version_patchlevel;
#define VIRTGPU_DRM_CONTEXT_MSM      1
#define VIRTGPU_DRM_CONTEXT_AMDGPU   2
#define VIRTGPU_DRM_CONTEXT_AMDXDNA  3
   uint32_t context_type;
   uint32_t pad;
};

/**
 * Defines the layout of shmem buffer used for host->guest communication.
 */
struct vdrm_shmem {
   /**
    * The sequence # of last cmd processed by the host
    */
   uint32_t seqno;

   /**
    * Offset to the start of rsp memory region in the shmem buffer.  This
    * is set by the host when the shmem buffer is allocated, to allow for
    * extending the shmem buffer with new fields.  The size of the rsp
    * memory region is the size of the shmem buffer (controlled by the
    * guest) minus rsp_mem_offset.
    *
    * The guest should use the vdrm_shmem_has_field() macro to determine
    * if the host supports a given field, ie. to handle compatibility of
    * newer guest vs older host.
    *
    * Making the guest userspace responsible for backwards compatibility
    * simplifies the host VMM.
    */
   uint32_t rsp_mem_offset;

#define vdrm_shmem_has_field(shmem, field) ({                             \
      struct vdrm_shmem *_shmem = &(shmem)->base;                         \
      (_shmem->rsp_mem_offset > offsetof(__typeof__(*(shmem)), field));   \
   })
};

/**
 * A Guest -> Host request header.
 */
struct vdrm_ccmd_req {
   uint32_t cmd;
   uint32_t len;
   uint32_t seqno;

   /* Offset into shmem ctrl buffer to write response.  The host ensures
    * that it doesn't write outside the bounds of the ctrl buffer, but
    * otherwise it is up to the guest to manage allocation of where responses
    * should be written in the ctrl buf.
    *
    * Only applicable for cmds that have a response message.
    */
   uint32_t rsp_off;
};

/**
 * A Guest <- Host response header.
 */
struct vdrm_ccmd_rsp {
   uint32_t len;
};

#define DEFINE_CAST(parent, child)                                             \
   static inline struct child *to_##child(const struct parent *x)              \
   {                                                                           \
      return (struct child *)x;                                                \
   }

#endif /* DRM_HW_H_ */
