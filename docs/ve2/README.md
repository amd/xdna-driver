# VE2 Workload Submission — End-to-End Reference

> **Scope.** This doc set explains how a workload is submitted to the **Versal AIE2** (a.k.a. **VE2 / aie2ps / Telluride**) device exposed by the **in-tree platform/auxiliary driver** at `src/driver/amdxdna/ve2_*.{c,h}` and the **`src/shim_ve2`** XRT shim. It is the reference design that the new T20 (`npu3_aie2ps`) variant inherits its execution model from — only the management transport differs.

## Why a ve2-specific doc set?

The amdxdna tree carries **three coexisting submission designs** today; they share UAPI but diverge sharply in who runs what:

| Variant         | Mgmt transport       | On-device cmd processor                  | Driver entry                |
|-----------------|----------------------|------------------------------------------|-----------------------------|
| **PCI npu1/3/4**| PCI BAR + MSI-X      | CERT firmware (uC), driver writes BAR DB | `aie2_*.c` / `aie4_pci.c`   |
| **VE2 (this)**  | AI Engine partition + CSR event reg | **CERT firmware on AIE uC**       | `ve2_*.c` (auxiliary drv)   |
| **T20**         | RPMsg / SHMEM mailbox| Same CERT/aie4 protocol as npu3          | `amdxdna_plat.c` + `npu3_aie2ps_regs.c` |

The ve2 path is the **most reference-architecture** one for the AIE silicon: the kernel allocates the HSA queue in DRAM-coherent memory, pre-loads CERT on every column, talks to the AIE through `aie_partition_*` APIs, and the host "doorbell" is just an AIE shim CSR write that raises an event the CERT firmware listens for. There is **no PCI BAR** and **no RPMsg control channel** — the kernel and CERT communicate via shared memory plus IRQs surfaced through the Xilinx AIE driver.

## Reading order

1. **[01-architecture.md](./01-architecture.md)** — Layer diagram, who runs what, where CERT fits, comparison to npu3/T20.
2. **[02-submit-flow.md](./02-submit-flow.md)** — Step-by-step end-to-end flow with sequence diagrams (`xrt::run::start` → `EXEC_CMD` ioctl → CERT → completion).
3. **[03-memory-model.md](./03-memory-model.md)** — BO backends (CMA / carvedout / ubuf), memory regions / `mem_bitmap`, instruction-code BO, args BO, HSA queue allocation.
4. **[04-hsa-queue-protocol.md](./04-hsa-queue-protocol.md)** — `struct hsa_queue` layout, packet types (direct vs indirect), doorbell, completion signaling, handshake region.

## Cheat sheet (the "10-second answer")

- **CERT exists on ve2.** It runs on the AIE microcontrollers and is loaded by the kernel at probe (`amdnpu/release_cert_ve2.elf` via `aie_load_cert_broadcast`). It is the on-device command processor that consumes `host_queue_packet`s and signals completion.
- **Userspace never touches the HSA ring.** The shim only sees DRM IOCTLs (`CREATE_HWCTX`, `CREATE_BO`, `EXEC_CMD`, `WAIT_CMD`). The kernel owns the `struct hsa_queue` (allocated via `dma_alloc_coherent` per hw_ctx), writes packets into it, and rings the doorbell.
- **The doorbell is an AIE event register write**, not an MMIO BAR poke or an RPMsg. `notify_fw_cmd_ready()` calls `aie_partition_write(VE2_EVENT_GENERATE_REG=0x34008, value=0xB6)`.
- **Memory comes from DT-described `memory-region` carveouts**, presented to user code as a per-hw_ctx `mem_bitmap` returned by `DRM_AMDXDNA_HWCTX_MEM_BITMAP`. The shim then ORs that bitmap into low bits of `amdxdna_drm_create_bo.flags` for subsequent allocations.
- **Instruction (DPU control code) BOs are normal CMA-backed `AMDXDNA_BO_SHARE` BOs**; their device addresses are placed inline in `host_queue_packet.exec_buf` (or in indirect packets for chained / multi-UC submits). There is no special "instruction heap".
- **Args are not a separate BO today.** XRT patches kernel arguments into the control-code stream during `xrt::module` finalize; `args_len` in `exec_buf` is set to 0 by the kernel.
- **Completion is polled in the kernel against `host_queue_header.read_index`** which CERT advances; status comes from a separate `hq_complete[]` "HQC" memory written by CERT. The shim blocks in `DRM_IOCTL_AMDXDNA_WAIT_CMD`.
