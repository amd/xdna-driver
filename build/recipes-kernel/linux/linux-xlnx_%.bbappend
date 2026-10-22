FILESEXTRAPATHS:prepend := "${THISDIR}/${PN}:"
SRC_URI:append = " file://bsp_vaiml.cfg"
KERNEL_FEATURES:append = " bsp_vaiml.cfg"

SRC_URI:append = " file://0001-xilinx-ai-engine-Protect-AXI-MM-access-during-reset-.patch"
SRC_URI:append = " file://0002-xilinx-ai-engine-Make-AXI-MM-reset-lock-conditional-.patch"
SRC_URI:append = " file://0003-driver-xilinx-ai-engine-Added-support-to-disable-int.patch"
SRC_URI:append = " file://0004-driver-xilinx-ai-engine-Added-support-to-disable-axi.patch"
SRC_URI:append = " file://0005-xilinx-ai-engine-fix-UC-AXIMM-transaction-timeout-on.patch"
SRC_URI:append = " file://0006-xilinx-ai-engine-Fix-aie_part_pm_ops-function-argume.patch"
SRC_URI:append = " file://0007-xilinx-ai-engine-Granularize-error-handling-init-options.patch"
SRC_URI:append = " file://0001-xilinx-ai-engine-part-init-optimizations.patch"
SRC_URI:append = " file://0002-aie-handshake-avoid-dmam_alloc_coherent-per-column-via-dma_addr.patch"
SRC_URI:append = " file://0010-xilinx-ai-engine-user-event1-irq-latency-fix.patch"
SRC_URI:append = " file://0008-xilinx-dma-tile-offset.patch"
SRC_URI:append = " file://0001-media-platform-xilinx-preprocess.patch"
SRC_URI:append = " file://0001-xilinx-ai-engine-Add-USER_EVENT1-initialization-support.patch"
SRC_URI:append = " file://0001-driver-dma-ai_layoutfomater.patch"

# Out-of-tree amdxdna calls hmm_range_fault(), exported only with
# CONFIG_HMM_MIRROR. That symbol is promptless and depends only on MMU.
# In-tree DRM_ACCEL_AMDXDNA selects it, but that option is x86/PCI-only, so
# on Versal select it from DRM_ACCEL (already enabled by bsp_vaiml.cfg).
# CONFIG_HMM_MIRROR=y in that fragment keeps do_kernel_configcheck quiet;
# olddefconfig would drop a fragment-only request.
SRC_URI:append = " file://0009-drivers-accel-select-HMM_MIRROR-for-out-of-tree-amdxdna.patch"

