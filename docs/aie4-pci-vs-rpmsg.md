# AIE4 Driver: PCI vs RPMsg vs Future Transport Comparison

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Device Bringup / Driver Probe](#device-bringup--driver-probe)
- [Management Message Send Path](#management-message-send-path)
- [Management Message Receive Path](#management-message-receive-path)
- [Doorbell (Command Submission Notification)](#doorbell-command-submission-notification)
- [Doorbell Completion (Firmware -> Host Notification)](#doorbell-completion-firmware---host-notification)
- [Transport Abstraction Layer](#transport-abstraction-layer)
- [Build System](#build-system)

---

## Architecture Overview

```
                         ┌─────────────────────────────────────────────┐
                         │              User Space (DRM/ioctl)         │
                         └────────────────────┬────────────────────────┘
                                              │
                         ┌────────────────────▼────────────────────────┐
                         │         amdxdna DRM/accel core              │
                         │  (amdxdna_pci_drv.c / amdxdna_rpmsg.c)     │
                         └────────────────────┬────────────────────────┘
                                              │
                         ┌────────────────────▼────────────────────────┐
                         │         aie4_send_msg_wait()                │
                         │         ring_doorbell()                     │
                         │                                             │
                         │   if (ndev->xcomm_ops)                      │
                         │       → xcomm_ops->send_msg()               │
                         │       → xcomm_ops->ring_doorbell()          │
                         │   else                                      │
                         │       → xdna_mailbox_send_msg() [MMIO]      │
                         │       → writel(0, doorbell_addr) [MMIO]     │
                         └───────┬─────────────────────┬───────────────┘
                                 │                     │
                    ┌────────────▼──────┐   ┌──────────▼────────────┐
                    │   PCI Mailbox     │   │   xcomm_ops backends  │
                    │   (MMIO ring buf) │   │   ┌────────────────┐  │
                    │                   │   │   │ RPMsg/VirtIO   │  │
                    │                   │   │   ├────────────────┤  │
                    │                   │   │   │ SHM+IPI (TODO) │  │
                    │                   │   │   └────────────────┘  │
                    └───────────────────┘   └───────────────────────┘
```

---

## Device Bringup / Driver Probe

### PCI Path

```
module_init(amdxdna_mod_init)
  └─ pci_register_driver(&amdxdna_pci_driver)
       └─ amdxdna_probe(pdev, id)                    [amdxdna_pci_drv.c]
            ├─ devm_drm_dev_alloc()                   alloc DRM device
            ├─ amdxdna_get_dev_info(pdev)              match PCI ID → dev_info
            ├─ drmm_mutex_init(&xdna->dev_lock)
            ├─ init_rwsem(&xdna->notifier_lock)
            ├─ amdxdna_iommu_init()                    IOMMU / PASID setup
            ├─ alloc_ordered_workqueue("notifier_wq")
            │
            ├─ xdna->dev_info->ops->init(xdna)  ═══►  aie4_pci_init()
            │    ├─ devm_kzalloc(ndev)                 alloc amdxdna_dev_hdl
            │    ├─ mutex_init(&ndev->aie4_lock)
            │    ├─ xa_init(&ndev->cert_comp_xa)
            │    │
            │    ├─ aie4_pcidev_init(ndev)
            │    │    ├─ pcim_enable_device()           enable PCI device
            │    │    ├─ dma_set_mask_and_coherent(64)  DMA mask
            │    │    ├─ pcim_iomap() × N bars          map MMIO BARs
            │    │    │   → ndev->mbox_base             mailbox BAR
            │    │    │   → ndev->rbuf_base             SRAM/ring buffer BAR
            │    │    │   → ndev->smu_base              SMU BAR
            │    │    │   → ndev->doorbell_base         doorbell BAR
            │    │    │   → ndev->psp_base              PSP BAR
            │    │    ├─ aie4_request_firmware()         load NPU + CERT FW
            │    │    ├─ aie4_prepare_firmware()         create PSP + SMU handles
            │    │    ├─ pci_set_master()
            │    │    ├─ aie4_alloc_work_buffer()       DMA work buffer
            │    │    │
            │    │    └─ aie4_hw_start(xdna)
            │    │         ├─ aie4_fw_load()
            │    │         │    ├─ aie4_smu_start()     power up clocks
            │    │         │    └─ aie4_psp_start()     load FW via PSP
            │    │         ├─ aie4_irq_init()
            │    │         │    └─ pci_alloc_irq_vectors(MSI-X)
            │    │         ├─ aie4_mailbox_init()
            │    │         │    ├─ aie4_fw_is_alive()   poll FW ready flag
            │    │         │    ├─ aie4_read_mbox_info() read ring buf layout
            │    │         │    ├─ xdna_mailbox_create() create mailbox device
            │    │         │    └─ xdna_mailbox_create_channel(MGMT)
            │    │         │         → ndev->mgmt_chann
            │    │         ├─ aie4_mgmt_fw_query()      query FW/AIE version
            │    │         ├─ aie4_mgmt_fw_init()       calibrate, attach buf
            │    │         ├─ aie4_pm_init()            power management
            │    │         ├─ aie4_partition_init()      create AIE partition
            │    │         └─ aie4_error_async_events_alloc()
            │    │
            │    ├─ aie4_iommu_init()                   PASID / SVA
            │    └─ aie4_xrsm_init()                    resource solver
            │
            ├─ amdxdna_sysfs_init()
            ├─ tdr_start()                              timeout detection
            ├─ drm_dev_register()                       expose /dev/accel/accelN
            ├─ amdxdna_dpt_init()                       debug/profile/trace
            └─ amdxdna_rpm_init()                       runtime PM
```

### RPMsg Path

```
module_init(amdxdna_rpmsg_init)
  └─ register_rpmsg_driver(&amdxdna_rpmsg_driver)
       │  id_table: { "rpmsg-aie-mgmt" }
       │  callback: amdxdna_rpmsg_rx_cb
       │
       └─ amdxdna_rpmsg_probe(rpdev)                  [amdxdna_rpmsg.c]
            ├─ devm_drm_dev_alloc()                    alloc DRM device
            ├─ xdna->dev_info = &amdxdna_rpmsg_dev_info  (minimal, no ops)
            ├─ drmm_mutex_init(&xdna->dev_lock)
            ├─ init_rwsem(&xdna->notifier_lock)
            │
            ├─ drmm_kzalloc(ndev)                      alloc amdxdna_dev_hdl
            ├─ drmm_kzalloc(rhdl)                      alloc amdxdna_rpmsg_hdl
            │
            │  ┌─ rhdl setup ─────────────────────┐
            │  │  rhdl->ndev  = ndev               │
            │  │  rhdl->rpdev = rpdev              │
            │  │  xa_init(&rhdl->msg_xa)           │    inflight message tracking
            │  │  mutex_init(&rhdl->msg_lock)      │
            │  └──────────────────────────────────┘
            │
            │  ┌─ ndev setup ─────────────────────┐
            │  │  ndev->xdna      = xdna           │
            │  │  ndev->xcomm_ops = &rpmsg_ops     │ ◄── transport wired here
            │  │  ndev->xcomm_hdl = rhdl           │
            │  │  xa_init(&ndev->cert_comp_xa)     │    doorbell completion tracking
            │  │  mutex_init(&ndev->aie4_lock)     │
            │  └──────────────────────────────────┘
            │
            │  NOT done (vs PCI):
            │    ✗ No pcim_enable_device / BAR mapping
            │    ✗ No firmware load (PSP/SMU)
            │    ✗ No IRQ allocation (MSI-X)
            │    ✗ No MMIO mailbox creation
            │    ✗ No IOMMU/PASID init
            │    ✗ No work buffer allocation
            │    ✗ No aie4_hw_start() sequence
            │
            ├─ alloc_ordered_workqueue("notifier_wq")
            ├─ amdxdna_sysfs_init()
            └─ drm_dev_register()                      expose /dev/accel/accelN
```

### Side-by-Side Comparison

| Step | PCI | RPMsg |
|------|-----|-------|
| **Bus binding** | `pci_register_driver` + PCI ID table | `register_rpmsg_driver` + service name `"rpmsg-aie-mgmt"` |
| **Parent device** | `struct pci_dev` | `struct rpmsg_device` |
| **DRM alloc** | `devm_drm_dev_alloc` | `devm_drm_dev_alloc` (same) |
| **Device handle** | `devm_kzalloc(ndev)` | `drmm_kzalloc(ndev)` + `drmm_kzalloc(rhdl)` |
| **Transport** | `ndev->mgmt_chann` (MMIO mailbox) | `ndev->xcomm_ops = &rpmsg_ops` |
| **BAR mapping** | 5+ PCI BARs mapped | None |
| **Firmware load** | PSP + SMU | Skipped (remote side owns HW) |
| **IRQ setup** | `pci_alloc_irq_vectors(MSI-X)` | None (RPMsg RX callback) |
| **Mailbox init** | `xdna_mailbox_create` + ring buffer | None |
| **IOMMU/PASID** | `iommu_dev_enable_feature(SVA)` | None |
| **FW handshake** | Query version, calibrate, partition | None (done by remote) |
| **DRM register** | `drm_dev_register` | `drm_dev_register` (same) |

---

## Management Message Send Path

A management message (e.g., create partition, query version, create context) flows
through `aie4_send_msg_wait()`, which dispatches based on `ndev->xcomm_ops`.

### PCI Path

```
caller (e.g. aie4_partition_init)
  │
  ▼
aie4_send_msg_wait(ndev, msg)                         [aie4_message.c]
  │  ndev->xcomm_ops == NULL → PCI mailbox path
  │
  ├─ xdna_send_msg_wait(xdna, ndev->mgmt_chann, msg)
  │    │
  │    ├─ xdna_mailbox_send_msg(chann, msg, TX_TIMEOUT) [amdxdna_mailbox.c]
  │    │    ├─ kzalloc(mb_msg)                          alloc mailbox_msg
  │    │    ├─ build xdna_msg_header                    set opcode, size, id
  │    │    ├─ memcpy payload into mb_msg->pkg
  │    │    ├─ mailbox_acquire_msgid()                   get slot in chan_xa
  │    │    ├─ mailbox_send_msg()
  │    │    │    ├─ write msg into MMIO ring buffer      memcpy_toio()
  │    │    │    └─ mailbox_set_tailptr()                update tail pointer
  │    │    └─ return 0
  │    │
  │    ├─ wait_for_completion_timeout(&hdl->comp, RX_TIMEOUT)
  │    │    (blocks until firmware responds via ISR → rx_worker → notify_cb)
  │    │
  │    └─ return hdl->error
  │
  └─ check AIE4_MSG_STATUS_SUCCESS
```

### RPMsg Path

```
caller (e.g. aie4_partition_init)
  │
  ▼
aie4_send_msg_wait(ndev, msg)                         [aie4_message.c]
  │  ndev->xcomm_ops != NULL → xcomm path
  │
  ├─ ndev->xcomm_ops->send_msg(ndev->xcomm_hdl, msg)
  │    │
  │    ▼
  │  amdxdna_rpmsg_send_msg(xcomm_hdl, msg)            [amdxdna_rpmsg.c]
  │    ├─ kzalloc(rpmsg_inflight_msg)                   alloc tracking struct
  │    ├─ mutex_lock(&rhdl->msg_lock)
  │    ├─ id = rhdl->next_msg_id++                      assign unique ID
  │    ├─ xa_insert(&rhdl->msg_xa, id, ifm)             track inflight msg
  │    ├─ mutex_unlock(&rhdl->msg_lock)
  │    │
  │    ├─ build rpmsg_msg_header
  │    │    .total_size = sizeof(hdr) + payload
  │    │    .id         = id
  │    │    .opcode     = msg->opcode
  │    │    .type       = RPMSG_MSG_MGMT                ◄── message type tag
  │    ├─ memcpy payload after header
  │    │
  │    ├─ rpmsg_send(rhdl->rpdev->ept, buf, total)
  │    │    └─ → VirtIO virtqueue → remote processor
  │    │
  │    └─ return 0
  │
  ├─ wait_for_completion_timeout(&hdl->comp, RX_TIMEOUT)
  │    (blocks until firmware responds via rpmsg_rx_cb → notify_cb)
  │
  └─ check AIE4_MSG_STATUS_SUCCESS
```

### Message Format Comparison

**PCI Mailbox Header** (`struct xdna_msg_header` in ring buffer):
```
┌──────────────┬──────────────┬──────────────┬──────────────┐
│ total_size   │ sz_ver       │ id           │ opcode       │
│ (u32)        │ (u32)        │ (u32)        │ (u32)        │
├──────────────┴──────────────┴──────────────┴──────────────┤
│                      payload (N bytes)                    │
└──────────────────────────────────────────────────────────┘
Written via memcpy_toio() into MMIO-mapped SRAM ring buffer.
```

**RPMsg Header** (`struct rpmsg_msg_header`):
```
┌──────────────┬──────────────┬──────────────┬──────────────┐
│ total_size   │ id           │ opcode       │ type         │
│ (__le32)     │ (__le32)     │ (__le32)     │ (__le32)     │
├──────────────┴──────────────┴──────────────┴──────────────┤
│                      payload (N bytes)                    │
└──────────────────────────────────────────────────────────┘
Sent via rpmsg_send() over VirtIO virtqueue.
type = RPMSG_MSG_MGMT (0) or RPMSG_MSG_DOORBELL (1).
```

---

## Management Message Receive Path

### PCI Path

```
Firmware writes response into I2X (inbound) ring buffer
  │
  ▼
MSI-X interrupt fires
  │
  ▼
mailbox_irq_handler(irq, mb_chann)                    [amdxdna_mailbox.c]
  └─ queue_work(mb_chann->work_q, &mb_chann->rx_work)
       │
       ▼
     mailbox_rx_worker()
       ├─ mailbox_irq_acknowledge()
       └─ loop: mailbox_get_msg(mb_chann)
            ├─ read tail/head from MMIO regs
            ├─ memcpy_fromio(header) from ring buffer
            ├─ mailbox_get_resp(header, data)
            │    ├─ xa_erase_irq(chan_xa, msg_id)       find inflight msg
            │    ├─ mb_msg->notify_cb(handle, data, sz)
            │    │    │
            │    │    ▼
            │    │  aie4_xdna_msg_cb(handle, data, size) [aie4_message.c]
            │    │    ├─ memcpy_fromio(cb_arg->data, data, size)
            │    │    └─ complete(&cb_arg->comp)         ◄── unblocks sender
            │    └─ kfree(mb_msg)
            └─ mailbox_set_headptr()                    advance head
```

### RPMsg Path

```
Remote processor sends response via VirtIO virtqueue
  │
  ▼
virtio_rpmsg_bus receives message
  │
  ▼
amdxdna_rpmsg_rx_cb(rpdev, data, len, priv, src)      [amdxdna_rpmsg.c]
  ├─ parse rpmsg_msg_header
  ├─ type = le32_to_cpu(hdr->type)
  │
  ├─ if type == RPMSG_MSG_DOORBELL:
  │    └─ amdxdna_rpmsg_doorbell_notify()              (see doorbell section)
  │
  ├─ if type == RPMSG_MSG_MGMT (or default):
  │    ├─ mutex_lock(&rhdl->msg_lock)
  │    ├─ ifm = xa_erase(&rhdl->msg_xa, id)            find inflight msg
  │    ├─ mutex_unlock(&rhdl->msg_lock)
  │    │
  │    ├─ ifm->notify_cb(handle, payload, payload_len)
  │    │    │
  │    │    ▼
  │    │  aie4_xdna_msg_cb(handle, data, size)          [aie4_message.c]
  │    │    ├─ memcpy_fromio(cb_arg->data, data, size)  (safe on normal memory)
  │    │    └─ complete(&cb_arg->comp)                  ◄── unblocks sender
  │    │
  │    └─ kfree(ifm)
  │
  └─ return 0
```

### Side-by-Side Comparison

| Aspect | PCI | RPMsg |
|--------|-----|-------|
| **Trigger** | MSI-X interrupt | VirtIO virtqueue callback |
| **Handler** | `mailbox_irq_handler` → workqueue | `amdxdna_rpmsg_rx_cb` (direct) |
| **Message source** | MMIO ring buffer (memcpy_fromio) | Kernel buffer from rpmsg framework |
| **ID tracking** | `chan_xa` (xarray per mailbox channel) | `rhdl->msg_xa` (xarray per rpmsg handle) |
| **Completion** | `aie4_xdna_msg_cb` → `complete()` | `aie4_xdna_msg_cb` → `complete()` (same) |
| **Demux** | One channel per type (mgmt/user) | Single endpoint, demux by `hdr->type` |

---

## Doorbell (Command Submission Notification)

The doorbell notifies firmware that a new command has been placed in the
UMQ (User Mode Queue). This is the **host → firmware** direction.

### PCI Path

```
aie4_hwctx_submit()                                   [aie4_hwctx.c]
  ├─ publish_cmd(ctx)                                  write cmd to UMQ
  └─ ring_doorbell(ctx)
       │  ndev->xcomm_ops == NULL
       │
       └─ writel(0, ctx->priv->doorbell_addr)
            │
            └─ MMIO write to PCI doorbell BAR
                 → firmware reads UMQ
```

### RPMsg Path

```
aie4_hwctx_submit()                                   [aie4_hwctx.c]
  ├─ publish_cmd(ctx)                                  write cmd to UMQ
  └─ ring_doorbell(ctx)
       │  ndev->xcomm_ops != NULL
       │
       └─ ndev->xcomm_ops->ring_doorbell(xcomm_hdl, hw_ctx_id)
            │
            ▼
          amdxdna_rpmsg_ring_doorbell(xcomm_hdl, hw_ctx_id) [amdxdna_rpmsg.c]
            ├─ build rpmsg_msg_header
            │    .total_size = sizeof(hdr)
            │    .id         = hw_ctx_id               ◄── identifies which context
            │    .opcode     = 0
            │    .type       = RPMSG_MSG_DOORBELL
            │
            └─ rpmsg_send(rhdl->rpdev->ept, &hdr, sizeof(hdr))
                 └─ → VirtIO virtqueue → remote firmware
```

### Comparison

| Aspect | PCI | RPMsg |
|--------|-----|-------|
| **Mechanism** | `writel(0, doorbell_addr)` — single MMIO write | `rpmsg_send()` — message over VirtIO |
| **Latency** | ~100ns (direct MMIO) | ~1-10us (virtqueue notify) |
| **Context ID** | Implicit (each context has its own doorbell MMIO page) | Explicit in `hdr->id = hw_ctx_id` |
| **Data sent** | No data, just a write to trigger | 16-byte header with type + context ID |

---

## Doorbell Completion (Firmware → Host Notification)

After firmware processes a command from the UMQ, it notifies the host that
the command is complete. This is the **firmware → host** direction.

### PCI Path

```
Firmware triggers MSI-X interrupt for the context's cert_comp
  │
  ▼
cert_comp_isr(irq, cert_comp)                         [aie4_pci.c]
  └─ wake_up_all(&cert_comp->waitq)                   unblock waiting thread


cert_comp setup (during aie4_create_context):
  aie4_lookup_cert_comp(ndev, msix_idx)
    ├─ kzalloc(cert_comp)
    ├─ init_waitqueue_head(&cert_comp->waitq)
    ├─ pci_irq_vector(pdev, msix_idx)                  get Linux IRQ number
    ├─ request_irq(irq, cert_comp_isr, "xdna_hsa")    register ISR
    └─ xa_store(&ndev->cert_comp_xa, msix_idx, cert_comp)
```

### RPMsg Path

```
Remote firmware sends RPMSG_MSG_DOORBELL message back
  │
  ▼
amdxdna_rpmsg_rx_cb(rpdev, data, len, priv, src)      [amdxdna_rpmsg.c]
  ├─ type == RPMSG_MSG_DOORBELL
  │
  └─ amdxdna_rpmsg_doorbell_notify(ndev, id)
       ├─ xa_lock_irqsave(&ndev->cert_comp_xa)
       ├─ cert_comp = xa_load(&ndev->cert_comp_xa, id) lookup by hw_ctx_id
       ├─ xa_unlock_irqrestore()
       │
       └─ wake_up_all(&cert_comp->waitq)               unblock waiting thread


cert_comp setup (during aie4_create_context):
  aie4_lookup_cert_comp(ndev, msix_idx)
    ├─ kzalloc(cert_comp)
    ├─ init_waitqueue_head(&cert_comp->waitq)
    ├─ ndev->xcomm_ops != NULL → skip IRQ setup        ◄── no PCI IRQ
    └─ xa_store(&ndev->cert_comp_xa, msix_idx, cert_comp)
```

### Comparison

| Aspect | PCI | RPMsg |
|--------|-----|-------|
| **Trigger** | MSI-X interrupt (hardware) | RPMsg message with `type=DOORBELL` |
| **ISR** | `cert_comp_isr` (IRQ context) | `amdxdna_rpmsg_rx_cb` (process context) |
| **Lookup** | ISR registered per-IRQ, implicit mapping | `xa_load(cert_comp_xa, hw_ctx_id)` |
| **Wake** | `wake_up_all(&cert_comp->waitq)` | `wake_up_all(&cert_comp->waitq)` (same) |
| **IRQ setup** | `pci_irq_vector` + `request_irq` | Skipped entirely |
| **Polling fallback** | `cert_timer` (1s timer) | Not needed |

---

## Transport Abstraction Layer

The `struct amdxdna_xcomm_ops` provides a pluggable transport interface:

```c
struct amdxdna_xcomm_ops {
    int (*send_msg)(void *xcomm_hdl,
                    const struct xdna_mailbox_msg *msg);
    int (*ring_doorbell)(void *xcomm_hdl, u32 hw_ctx_id);
    void (*fini)(void *xcomm_hdl);
};
```

### Current Implementations

| Field | PCI (no xcomm_ops) | RPMsg |
|-------|-------------------|-------|
| `xcomm_ops` | `NULL` | `&amdxdna_rpmsg_xcomm_ops` |
| `xcomm_hdl` | `NULL` | `struct amdxdna_rpmsg_hdl *` |
| `send_msg` | N/A (uses `mgmt_chann`) | `amdxdna_rpmsg_send_msg` |
| `ring_doorbell` | N/A (uses `writel`) | `amdxdna_rpmsg_ring_doorbell` |
| `fini` | N/A | `amdxdna_rpmsg_fini` |

### Adding a New Transport (e.g., Shared Memory + IPI)

To add a custom shared-memory + IPI transport for platforms like Telluride:

1. Create `amdxdna_shmem.c` with a new handle struct:

```c
struct amdxdna_shmem_hdl {
    struct amdxdna_dev_hdl  *ndev;
    void __iomem            *shmem_base;    /* shared memory region */
    int                      ipi_irq;       /* IPI interrupt */
    struct xarray            msg_xa;         /* inflight tracking */
    /* ... */
};
```

2. Implement the ops:

```c
static const struct amdxdna_xcomm_ops amdxdna_shmem_xcomm_ops = {
    .send_msg      = amdxdna_shmem_send_msg,
    .ring_doorbell = amdxdna_shmem_ring_doorbell,
    .fini          = amdxdna_shmem_fini,
};
```

3. Register as a platform driver (device tree) and set `ndev->xcomm_ops` in probe.

4. **No changes needed** in `aie4_message.c`, `aie4_hwctx.c`, or `aie4_pci.c` --
   they already dispatch through `xcomm_ops` at runtime.

### Dispatch Logic

```c
/* aie4_message.c — send path */
if (ndev->xcomm_ops)
    ret = ndev->xcomm_ops->send_msg(ndev->xcomm_hdl, msg);  /* RPMsg / SHM+IPI */
else
    ret = xdna_send_msg_wait(xdna, ndev->mgmt_chann, msg);  /* PCI MMIO */

/* aie4_hwctx.c — doorbell path */
if (ndev->xcomm_ops)
    ndev->xcomm_ops->ring_doorbell(ndev->xcomm_hdl, hw_ctx_id);  /* RPMsg / SHM+IPI */
else
    writel(0, ctx->priv->doorbell_addr);                          /* PCI MMIO */

/* aie4_pci.c — cert_comp IRQ setup */
if (ndev->xcomm_ops || enable_aie4_polling)
    goto skip;  /* non-PCI transports handle notifications via their own RX path */
/* ... pci_irq_vector + request_irq ... */
```

---

## Build System

### Makefile (`src/driver/amdxdna/Makefile`)

```makefile
# XDNA_BUS_TYPE selects the transport:
#   pci   → standard PCI driver (default)
#   of    → device tree / platform driver
#   rpmsg → RPMsg over VirtIO

ifeq ($(XDNA_BUS_TYPE), rpmsg)
PCI = n
OF = n
RPMSG = y
endif

ifeq ($(XDNA_BUS_TYPE), rpmsg)
DEFINES += -DCONFIG_AMDXDNA_RPMSG
endif

KBUILD_ARGS := OFT_CONFIG_AMDXDNA_PCI=$(PCI) \
               OFT_CONFIG_AMDXDNA_OF=$(OF)    \
               OFT_CONFIG_AMDXDNA_RPMSG=$(RPMSG)
```

### Kbuild (`src/driver/amdxdna/Kbuild`)

```makefile
# PCI build includes: aie2 + aie4 + PSP + SMU + mailbox + SRIOV + ...
amdxdna-$(OFT_CONFIG_AMDXDNA_PCI) += \
    aie2_pci.o aie4_pci.o aie_psp.o aie_smu.o amdxdna_mailbox.o ...

# RPMsg build includes: aie4 core files + RPMsg transport (no PSP/SMU/mailbox)
amdxdna-$(OFT_CONFIG_AMDXDNA_RPMSG) += \
    aie4_pci.o aie4_hwctx.o aie4_message.o aie4_solver.o \
    aie4_debugfs.o aie4_devel.o aie4_error.o aie4_pm.o aie4_dpt.o \
    amdxdna_rpmsg.o
```

### What Each Bus Type Compiles

| Object file | PCI | RPMsg | Notes |
|------------|-----|-------|-------|
| `amdxdna_pci_drv.o` | Yes | Yes | `module_init` guarded by `#ifndef CONFIG_AMDXDNA_RPMSG` |
| `amdxdna_rpmsg.o` | No | Yes | RPMsg probe/remove, module_init |
| `amdxdna_mailbox.o` | Yes | No | MMIO ring buffer mailbox |
| `aie_psp.o` | Yes | No | PSP firmware loader |
| `aie_smu.o` | Yes | No | SMU clock/power |
| `aie4_pci.o` | Yes | Yes | PCI-specific functions guarded at runtime |
| `aie4_hwctx.o` | Yes | Yes | `ring_doorbell` dispatches via `xcomm_ops` |
| `aie4_message.o` | Yes | Yes | `aie4_send_msg_wait` dispatches via `xcomm_ops` |
| `aie2_*.o` | Yes | No | AIE2 generation (PCI only) |
