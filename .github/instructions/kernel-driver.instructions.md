---
applyTo: "drivers/accel/amdxdna/**"
---
# Kernel driver design facts

- AIE4 is cache coherent. Syncing a BO from the device is a no-op by design.
- An attached debug buffer keeps the device out of runtime suspend. It is released
  when the context is suspended, reset or destroyed (aie4_hwctx_destroy()) and is
  not restored; user space recreates the context and configures it again.
- If firmware stops responding, BOs are released on teardown like the queue BO
  (umq_bo); a device reset is what stops firmware. Per-BO tracking for this case is
  intentionally not done.
- Config hwctx params: DRM_AMDXDNA_HWCTX_ASSIGN/REMOVE_DBG_BUF take a BO handle in
  param_val (AIE2). DRM_AMDXDNA_HWCTX_ASSIGN/REMOVE_FW_BUF take a pointer to
  struct amdxdna_fw_buffer_metadata, copied into the kernel (AIE4). Values start at 4
  because 3 is used by the user-space header.
- An attached AIE4 debug buffer is referenced in hwctx priv fw_buf_bo[] until a
  successful detach or context fini; at most one buffer per type per context.
