# Review context for xdna-driver

## Layout
- drivers/accel/amdxdna/: DRM accel kernel driver (amdxdna.ko), Linux upstream style.
  - aie2_*: AIE2 backend (NPU1, NPU4, NPU5, NPU6).
  - aie4_*: AIE4 backend (NPU3), PCI classic and SR-IOV VF ops.
- include/uapi/drm/amdxdna_accel.h: kernel uAPI, kept in sync with the upstream header.
- src/shim/: XRT plugin (libxrt_driver_xdna.so); host/ and virtio/ platforms, kmq/ and umq/.
- src/vxdna/: virtio renderer that forwards guest requests to the host driver.
- src/include/uapi/drm_local/amdxdna_accel.h: user-space copy of the uAPI, also used by
  shim_ve2. Values and struct layouts must match the kernel header.

## Release model
- The kernel driver and the XRT plugin are always released together. Compatibility
  with older shim binaries is not required.

## Upstream parity
- Some AIE4 code deliberately mirrors the upstream Linux driver, for example
  aie4_hwctx_cfg_fw_buf(). Prefer keeping it identical to upstream over local-only
  changes.

## Rules
- Kernel code follows Linux kernel style and passes scripts/checkpatch.pl --strict;
  the driver builds with -Werror.
- Do not reference internal code names, device names or unpublished registers.
