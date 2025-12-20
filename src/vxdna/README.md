# vxdna - Virtio XDNA Renderer Library

Multi-device library for AMD XDNA accelerators in virtualized environments, providing a userspace rendering backend for the virtio-gpu accelerator context protocol.

## Overview

The vxdna library enables AMD NPU (Neural Processing Unit) access from virtual machines through the virtio-gpu protocol. It implements the host-side backend that processes commands from guest VMs and translates them into native AMDXDNA driver calls.

Key features:
- **Cookie-based device management** - Multiple independent device instances
- **CRTP-based architecture** - Compile-time polymorphism for efficiency
- **Thread-safe operations** - Mutex-protected lookup tables
- **DRM GEM integration** - Native buffer object management
- **Timeline fence synchronization** - Async command completion with syncobj

## Architecture

### Class Hierarchy

```
vaccel<T, ContextType>          # Device template base class
    └── vxdna                   # AMDXDNA device implementation

vaccel_context<Derived, DeviceType>  # Context template base class (CRTP)
    └── vxdna_context                # AMDXDNA context implementation
        └── vxdna_hwctx              # Hardware context (nested class)

vaccel_map<Key, Value>          # Thread-safe hash map wrapper
vaccel_resource                 # GPU resource (buffer object)
vaccel_fence                    # Fence synchronization object
vxdna_bo                        # AMDXDNA buffer object
```

### Per-Device Tables

Each device maintains thread-safe lookup tables:

| Table | Key Type | Value Type | Purpose |
|-------|----------|------------|---------|
| Resource Table | `uint32_t` | `vaccel_resource` | GPU buffer objects and DMA-BUF exports |
| Context Table | `uint32_t` | `vxdna_context` | Independent command streams |
| Fence Table | `uint64_t` | `vaccel_fence` | Timeline synchronization points |

### Per-Context Tables

Each context maintains:

| Table | Key Type | Value Type | Purpose |
|-------|----------|------------|---------|
| BO Table | `uint32_t` | `vxdna_bo` | Buffer objects owned by context |
| HW Context Table | `uint32_t` | `vxdna_hwctx` | Hardware execution contexts |

## API Reference

### Device Management

```c
#include <vaccel.h>

// Create device with callbacks
int vaccel_create(void *cookie, uint32_t capset_id,
                  const struct vaccel_callbacks *callbacks);

// Destroy device and all resources
void vaccel_destroy(void *cookie);
```

The `cookie` is an opaque identifier (typically from QEMU's virtio-gpu backend). The `callbacks` structure provides:
- `get_device_fd()` - Returns the DRM file descriptor for the device
- `write_context_fence()` - Signals fence completion to the guest

### Capability Set

```c
// Get capset version and size
int vaccel_get_capset_info(void *cookie, uint32_t *max_version, uint32_t *max_size);

// Fill capset structure
int vaccel_fill_capset(void *cookie, uint32_t capset_size, void *capset_buf);
```

Returns `vaccel_drm_capset` structure with:
- `wire_format_version` - Protocol version
- `version_major/minor/patchlevel` - Library version
- `context_type` - `VIRTACCEL_DRM_CONTEXT_AMDXDNA`

### Context Management

```c
// Create context with flags and optional debug name
int vaccel_create_ctx_with_flags(void *cookie, uint32_t ctx_id,
                                  uint32_t ctx_flags, uint32_t nlen,
                                  const char *name);

// Destroy context
void vaccel_destroy_ctx(void *cookie, uint32_t ctx_id);
```

Each context gets its own DRM file descriptor via `dup()` for isolation.

### Resource Blob Management

```c
struct vaccel_create_resource_blob_args {
    uint32_t res_handle;        // Unique resource ID
    uint32_t ctx_id;            // Owning context
    uint32_t blob_mem;          // VIRTGPU_BLOB_MEM_GUEST or VIRTGPU_BLOB_MEM_HOST3D
    uint32_t blob_flags;        // Creation flags
    uint64_t blob_id;           // Blob type identifier
    uint64_t size;              // Size in bytes
    const struct iovec *iovecs; // IO vectors (guest memory)
    uint32_t num_iovs;          // Number of IO vectors
};

int vaccel_create_resource_blob(void *cookie,
                                 const struct vaccel_create_resource_blob_args *args);

int vaccel_destroy_resource_blob(void *cookie, uint32_t res_handle);

// Map/unmap for host memory blobs
int vaccel_resource_map(void *cookie, uint32_t res_id, void **data, size_t *size);
int vaccel_resource_unmap(void *cookie, uint32_t res_id);
```

### Command Submission

```c
// Submit context command buffer
int vaccel_submit_ccmd(void *cookie, uint32_t ctx_id,
                        const void *ccmd, uint32_t ccmd_size);

// Submit fence for async completion
int vaccel_submit_fence(void *cookie, uint32_t ctx_id,
                         uint32_t flags, uint32_t ring_idx,
                         uint64_t fence_id);
```

Commands are dispatched to AMDXDNA-specific handlers based on command type.

### Supported CCMD Operations

| Command | Description |
|---------|-------------|
| `init` | Initialize context with response resource |
| `create_bo` | Create buffer object (DEV, SHMEM, CMD types) |
| `destroy_bo` | Destroy buffer object |
| `create_ctx` | Create hardware execution context |
| `destroy_ctx` | Destroy hardware context |
| `config_ctx` | Configure hardware context parameters |
| `exec_cmd` | Execute command on hardware context |
| `wait_cmd` | Wait for command completion with timeout |
| `get_info` | Query device/driver information |
| `read_sysfs` | Read sysfs attributes |

## Logging

Debug logging is controlled via the `VXDNA_DEBUG` environment variable:

```bash
export VXDNA_DEBUG=1    # Enable debug output
export VXDNA_DEBUG=0    # Disable (default)
```

Log functions:
```c
vxdna_err(fmt, ...)     // Error messages (always printed)
vxdna_info(fmt, ...)    // Info messages
vxdna_dbg(fmt, ...)     // Debug messages (when VXDNA_DEBUG=1)
```

## Building

### Prerequisites

- CMake >= 3.10
- C++17 compiler
- libdrm development headers
- pthread library

### Build with CMake

```bash
# From xdna-driver root
mkdir build && cd build
cmake -DBUILD_VXDNA=ON ..
make vxdna

# Or use the build script
./build/build.sh -vxdna
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_VXDNA` | OFF | Enable vxdna library build |
| `BUILD_VXDNA_TESTING` | OFF | Build and run unit tests |

### Feature Detection

CMake automatically detects:
- `HAVE_DRM_SET_CLIENT_NAME` - DRM client name ioctl support
- `HAVE_STRUCT_IOVEC` - System iovec availability

### Run Tests

```bash
./build/build.sh -vxdna -vxdna_test
# Or manually:
cd build && ctest --output-on-failure
```

## Installation

```bash
cmake --install build --component xrt_plugin
```

Installs:
- `libvxdna.so.1.0.0` - Shared library
- `vaccel.h` - Public header
- `vxdna.pc` - pkg-config file

## Example Usage

```c
#include <vaccel.h>

// Callback implementations
static int get_fd(void *cookie) {
    return virtio_gpu_get_drm_fd(cookie);
}

static void write_fence(void *cookie, uint32_t ctx_id,
                         uint32_t ring_idx, uint64_t fence_id) {
    virtio_gpu_signal_fence(cookie, ctx_id, ring_idx, fence_id);
}

int main() {
    struct vaccel_callbacks cbs = {
        .get_device_fd = get_fd,
        .write_context_fence = write_fence,
    };

    void *cookie = virtio_gpu_device_cookie;

    // Create device
    int ret = vaccel_create(cookie, VIRACCEL_CAPSET_ID_AMDXDNA, &cbs);
    if (ret < 0) return ret;

    // Create response buffer to get ccmd response message
    // (Refer to platform_virtio.cpp for details.)
    int dev_fd = get_fd(cookie);
    constexpr size_t resp_buf_size = 4096; // adjust size as needed
    uint32_t resp_res_id = 0;

    // Create a virtgpu resource for the response buffer
    struct drm_virtgpu_resource_create_blob resp_blob = {
        .blob_mem   = VIRTGPU_BLOB_MEM_GUEST,
        .blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE,
        .size       = resp_buf_size,
        .blob_id    = 0,
    };
    int ret_blob = ioctl(dev_fd, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &resp_blob);
    if (ret_blob)
        return ret_blob;
    resp_res_id = resp_blob.res_handle;

    // Register the response buffer with the device
    // This lets the device know where to write ccmd responses
    register_resp_buf(dev_fd, resp_res_id);

    // Check response buffer to get the result
    void *resp_buf = mmap(NULL, resp_buf_size, PROT_READ, MAP_SHARED, dev_fd, 0);
    if (resp_buf == MAP_FAILED) {
        perror("mmap response buffer");
        return -1;
    }

    // Create context
    ret = vaccel_create_ctx_with_flags(cookie, 1, 0, 0, NULL);

    // Submit commands (from guest VM)
    ret = vaccel_submit_ccmd(cookie, 1, cmd_buf, cmd_size);

    // Interpret the response as needed; for example, print first few bytes
    printf("Response buffer first 16 bytes:");
    for (int i = 0; i < 16 && i < resp_buf_size; ++i) {
        printf(" %02x", ((unsigned char*)resp_buf)[i]);
    }
    printf("\n");

    munmap(resp_buf, resp_buf_size);

    // Cleanup
    vaccel_destroy_ctx(cookie, 1);
    vaccel_destroy(cookie);

    return 0;
}
```

## Thread Safety

All lookup tables use `vaccel_map<K,V>` which wraps `std::unordered_map` with mutex protection:

- Device table: Global mutex for device lookup
- Per-device tables: Each device has independent table locks
- Per-context tables: Each context has independent table locks
- Fence polling: Dedicated thread per hardware context with condition variable

## Implementation Details

### Buffer Object Types

| Type | Description | Memory |
|------|-------------|--------|
| `AMDXDNA_BO_DEV` | Device-only memory | NPU SRAM |
| `AMDXDNA_BO_SHMEM` | Shared memory | System RAM (mmap'd) |
| `AMDXDNA_BO_CMD` | Command buffer | System RAM |

### Hardware Context

Each `vxdna_hwctx` manages:
- DRM hardware context handle
- Timeline syncobj for fence tracking
- Polling thread for async completion
- Pending fence queue with condition variable

### Fence Flow

1. Guest submits `exec_cmd` → Returns sequence number
2. Guest submits `wait_cmd` → Sets sync point and timeout
3. Guest submits fence → Polling thread waits on syncobj
4. Fence signals → `write_context_fence` callback notifies guest

## License

This project is licensed under the **MIT License** - see the `LICENSE` file for details.

## References

- [AMD XDNA Driver](https://github.com/amd/xdna-driver) - Host kernel driver
- [virglrenderer](https://gitlab.freedesktop.org/virgl/virglrenderer) - Architecture inspiration
- [libdrm](https://gitlab.freedesktop.org/mesa/drm) - DRM interface library

---

Copyright (c) 2025 Advanced Micro Devices, Inc.
