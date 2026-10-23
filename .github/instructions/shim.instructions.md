---
applyTo: "src/shim/**,src/vxdna/**"
---
# Shim facts

- On virtio, hcall(req) only waits for transport; use the overload with a response
  buffer when the host result matters, so host ioctl errors are thrown.
- uc_dbg_buffer tracks its attachment in m_ctx_id. It is set only by a successful
  config() and cleared only by a successful detach, so a failed detach is retried by
  unconfig() or the destructor.
