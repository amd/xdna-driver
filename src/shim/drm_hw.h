/*
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: MIT
 */

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


struct virgl_renderer_capset_drm {
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
   union {
      struct {
         uint32_t has_cached_coherent;
         uint32_t priorities;
         uint64_t va_start;
         uint64_t va_size;
         uint32_t gpu_id;
         uint32_t gmem_size;
         uint64_t gmem_base;
         uint64_t chip_id;
         uint32_t max_freq;
         uint32_t highest_bank_bit;
         uint64_t ubwc_swizzle;
         uint64_t macrotile_mode;
         uint32_t has_raytracing;  /* VIRTGPU_CAP_BOOL_x */
         uint32_t has_preemption;  /* VIRTGPU_CAP_BOOL_x */
         uint64_t uche_trap_base;
      } msm;  /* context_type == VIRTGPU_DRM_CONTEXT_MSM */
      struct {
         uint32_t address32_hi;
         uint32_t __pad;
#ifdef ENABLE_DRM_AMDGPU
         struct amdgpu_buffer_size_alignments alignments;
         struct amdgpu_gpu_info gpu_info;
#endif
         char marketing_name[128];
      } amdgpu;   /* context_type == VIRTGPU_DRM_CONTEXT_AMDGPU */
   } u;
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
