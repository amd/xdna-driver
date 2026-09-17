#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

# Generate driver/amdxdna/config_kernel.h by feature-testing the kernel headers.

set -e

# ---- Obtain hash of this script -----------------------------------------
SCRIPT_HASH="$(sha256sum "$0" | awk '{print $1}')"

# ---- Locate kernel source tree -----------------------------------------
# Priority:
#   1) $KERNEL_VER (Can set this from CMake)
#   2) $kernelver (DKMS gives this)
#   3) $(uname -r) (Fall back to current running kernel)
KERNEL_VER="${KERNEL_VER:-${kernelver:-$(uname -r)}}"
KERNEL_DIR="/lib/modules/${KERNEL_VER}"
KERNEL_SRC="${KERNEL_SRC:-${KERNEL_DIR}/build}"
KERNEL_CMN="${KERNEL_DIR}/source"

if [ ! -d "$KERNEL_SRC/include/linux" ] && \
   [ ! -d "$KERNEL_CMN/include/linux" ]; then
    echo "ERROR: Cannot find kernel headers under $KERNEL_SRC or $KERNEL_CMN" >&2
    exit 1
fi

# ---- Output header path ------------------------------------------------
OUT="${OUT:-drivers/accel/amdxdna/config_kernel.h}"

# ---- Helper: extract value from $OUT ----------------------------
get_hdr_val() {
    key="$1"
    sed -n "s|^.*/\\* CONFIG_KERNEL: $key=\\([^ ]*\\) .*|\\1|p" "$OUT" 2>/dev/null
}

# ---- Check if $OUT is up-to-date ----------------------------
if [ -f "$OUT" ]; then
    OLD_KVER="$(get_hdr_val kernelver)"
    OLD_HASH="$(get_hdr_val script_sha256)"

    if [ "$OLD_KVER" = "$KERNEL_VER" ] &&
       [ "$OLD_HASH" = "$SCRIPT_HASH" ]; then
	echo ">>> $(pwd)/${OUT} is up-to-date (kernel=$KERNEL_VER)" >&2
        exit 0
    fi
fi

# ---- Detect whether the kernel was built with clang ------------------
# If so, pass LLVM=1 to make so that the same toolchain is used for conftests.
USE_LLVM=""
if [ -e "${KERNEL_SRC}/.config" ]; then
    if grep -q "CONFIG_CC_IS_CLANG=y" "${KERNEL_SRC}/.config" 2>/dev/null; then
        USE_LLVM="LLVM=1"
    fi
elif [ -e /proc/config.gz ]; then
    if zgrep -q "CONFIG_CC_IS_CLANG=y" /proc/config.gz 2>/dev/null; then
        USE_LLVM="LLVM=1"
    fi
elif [ -e "/boot/config-$KERNEL_VER" ]; then
    if grep -q "CONFIG_CC_IS_CLANG=y" "/boot/config-$KERNEL_VER" 2>/dev/null; then
        USE_LLVM="LLVM=1"
    fi
fi

echo ">>> Probing kernel features in $KERNEL_SRC..." >&2
echo ">>> Output file: $(pwd)/${OUT}" >&2

# ---- Helper: try to compile a small snippet ----------------------------
# Usage:
#   try_compile MACRO_NAME << 'EOF'
#   #include <linux/...>
#   int main(void) { ...; return 0; }
#   EOF
#
# The code snippet is compiled as a out-of-tree kernel module.
# If compilation succeeds, we add "#define MACRO_NAME 1" to the header.

try_compile() {
    macro="$1"
    shift

    tmpdir=$(mktemp -d /tmp/conftest-XXXXXX)
    conftest_c="$tmpdir/conftest.c"
    conftest_mk="$tmpdir/Makefile"

    # Minimal Kbuild for an external module
    cat > "$conftest_mk" <<EOF
obj-m := conftest.o
EOF

    # Preamble: module metadata to satisfy modpost
    cat > "$conftest_c" <<EOF
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("amdxdna conftest");
EOF

    # Append the actual test code from stdin
    cat >> "$conftest_c"

    # Now build it like your real driver ($USE_LLVM intentionally unquoted to avoid empty arg)
    if make -s -C "$KERNEL_SRC" M="$tmpdir" modules $USE_LLVM >/dev/null 2>&1; then
        echo "#define $macro 1" >> "$OUT"
        echo ">>>  + $macro: yes" >&2
    else
        echo ">>>  - $macro: no" >&2
    fi

    rm -rf "$tmpdir"
}

# ---- Sanity-check the build toolchain ----------------------------------
# A trivial module must always compile. If this fails, objtool or the
# compiler is broken and all try_compile results would be false negatives.
_canary_dir=$(mktemp -d /tmp/conftest-XXXXXX)
cat > "$_canary_dir/Makefile" <<EOF
obj-m := conftest.o
EOF
cat > "$_canary_dir/conftest.c" <<EOF
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("amdxdna conftest");
static int __init conftest_init(void) { return 0; }
static void __exit conftest_exit(void) {}
module_init(conftest_init);
module_exit(conftest_exit);
EOF
if ! _canary_err=$(make -s -C "$KERNEL_SRC" M="$_canary_dir" modules $USE_LLVM 2>&1); then
    echo "ERROR: Kernel module build sanity check failed." >&2
    echo "ERROR: Build output:" >&2
    echo "$_canary_err" | sed 's/^/  /' >&2
    echo "" >&2
    echo "ERROR: Diagnosis steps:" >&2
    echo "  1. Check objtool:  ldd $KERNEL_SRC/tools/objtool/objtool" >&2
    echo "     If a .so is missing, symlink the installed version, e.g.:" >&2
    echo "     sudo ln -s /usr/lib/x86_64-linux-gnu/libopcodes-<ver>-system.so \\" >&2
    echo "                /usr/lib/x86_64-linux-gnu/libopcodes-<required-ver>-system.so" >&2
    echo "  2. Check kernel headers exist: ls $KERNEL_SRC/include/linux/module.h" >&2
    echo "  3. Reproduce manually: make -C $KERNEL_SRC M=$_canary_dir modules $USE_LLVM" >&2
    rm -rf "$_canary_dir"
    exit 1
fi
rm -rf "$_canary_dir"
echo ">>> Toolchain sanity check passed." >&2

# ---- Write header preamble ---------------------------------------------

cat > "$OUT" <<EOF
/* Auto-generated by $(basename "$0"). Do not edit. */
/* CONFIG_KERNEL: kernelver=$KERNEL_VER */
/* CONFIG_KERNEL: script_sha256=$SCRIPT_HASH */

#ifndef AMDXDNA_CONFIG_KERNEL_H
#define AMDXDNA_CONFIG_KERNEL_H

/* Detected kernel features: */

EOF

#
# Add/remove tests here as needed.
# Please test it manually before adding the code snippet here.
#
# To test manually, simply create a directory under /tmp. Add two files under it as below:
#
# 1. Makefile with content:
# obj-m := test.o
# 2. test.c with content:
# #include <linux/module.h>
# MODULE_LICENSE("GPL");
# MODULE_DESCRIPTION("amdxdna conftest");
# <your-test-code-snippet-here>
#
# Run make -s -C /lib/modules/`uname -r`/build M=<your-directory> modules
# Make sure you see expected behavior with the compilation.
#


# Test system_percpu_wq in 6.17+:
# struct workqueue_struct *system_percpu_wq
try_compile HAVE_system_percpu_wq << 'EOF'
#include <linux/workqueue.h>
int main(void)
{
	struct work_struct *a = NULL;

	queue_work(system_percpu_wq, a);
	return 0;
}
EOF
cat >> "$OUT" <<'EOF'
#ifndef HAVE_system_percpu_wq
#define system_percpu_wq	system_wq
#endif
EOF

# Test MODULE_IMPORT_NS signature in 6.13+:
# #define MODULE_IMPORT_NS(ns)
try_compile HAVE_6_13_MODULE_IMPORT_NS << 'EOF'
#include <linux/module.h>
#include <linux/dma-buf.h>
int main(void)
{
	MODULE_IMPORT_NS("DMA_BUF");

	struct dma_buf *a = NULL;
	struct iosys_map *b = NULL;
	(void)dma_buf_vmap(a, b);
	return 0;
}
EOF

# Test drm_gem_vmap()/drm_gem_vunmap signature in 6.16+:
# int drm_gem_vmap(struct drm_gem_object *obj, struct iosys_map *map)
# void drm_gem_vunmap(struct drm_gem_object *obj, struct iosys_map *map)
try_compile HAVE_6_16_drm_gem_vmap_vunmap << 'EOF'
#include <drm/drm_gem.h>
int main(void)
{
	struct drm_gem_object *a = NULL;
	struct iosys_map *b = NULL;

	(void)drm_gem_vmap(a, b);
	(void)drm_gem_vunmap(a, b);
	return 0;
}
EOF
cat >> "$OUT" <<'EOF'
#ifndef HAVE_6_16_drm_gem_vmap_vunmap
#define drm_gem_vmap(bo, map)	drm_gem_vmap_unlocked(bo, map)
#define drm_gem_vunmap(bo, map)	drm_gem_vunmap_unlocked(bo, map)
#endif
EOF

# Test dma_buf_ops->cache_sgt_mapping in 6.15-:
# struct dma_buf_ops {
#         bool cache_sgt_mapping;
#         ...
# }
try_compile HAVE_cache_sgt_mapping << 'EOF'
#include <linux/dma-buf.h>
int main(void)
{
	const struct dma_buf_ops amdxdna_dmabuf_ops = {
		.cache_sgt_mapping = true,
	};

	return 0;
}
EOF

# Test iommu_paging_domain_alloc_flags() signature in 6.13+:
# struct iommu_domain *iommu_paging_domain_alloc_flags(struct device *dev, unsigned long flags)
try_compile HAVE_iommu_paging_domain_alloc_flags << 'EOF'
#include <linux/iommu.h>
int main(void)
{
	struct device *a = NULL;
	unsigned long b = 0;
	(void)iommu_paging_domain_alloc_flags(a, b);
	return 0;
}
EOF

# Test iommu_paging_domain_alloc() signature in 6.13+:
# struct iommu_domain *iommu_paging_domain_alloc(struct device *dev)
try_compile HAVE_iommu_paging_domain_alloc << 'EOF'
#include <linux/iommu.h>
int main(void)
{
	struct device *a = NULL;
	(void)iommu_paging_domain_alloc(a);
	return 0;
}
EOF

# Test xen_phy_dma_ops signature:
# const struct dma_map_ops xen_phy_dma_ops;
try_compile HAVE_xen_phy_dma_ops << 'EOF'
#include <xen/phy-dma-ops.h>
int main(void)
{
	const struct dma_map_ops *a = &xen_phy_dma_ops;
	return 0;
}
EOF

# Test kmalloc wrapper APIs (all introduced in 7.0):
#   kzalloc_obj, kzalloc_flex, kmalloc_flex,
#   kmalloc_objs, kzalloc_objs, kvzalloc_objs, kvmalloc_objs
# One compilation test is sufficient since they were all added together.
try_compile HAVE_7_0_kmalloc_ops << 'EOF'
#include <linux/slab.h>
int main(void)
{
	struct my_obj { int c; int data[]; };
	struct my_obj *p;
	int *q;

	p = kzalloc_obj(*p);
	p = kzalloc_flex(*p, data, 1);
	p = kmalloc_flex(*p, data, 1);
	q = kmalloc_objs(*q, 4);
	q = kzalloc_objs(*q, 4);
	q = kvzalloc_objs(*q, 4);
	q = kvmalloc_objs(*q, 4);
	return 0;
}
EOF
cat >> "$OUT" <<'EOF'
#ifndef HAVE_7_0_kmalloc_ops
#define kzalloc_obj(obj)		kzalloc(sizeof(obj), GFP_KERNEL)
#define kzalloc_flex(obj, member, n)	kzalloc(struct_size(&(obj), member, n), GFP_KERNEL)
#define kmalloc_flex(obj, member, n)	kmalloc(struct_size(&(obj), member, n), GFP_KERNEL)
#define kmalloc_objs(obj, n)		kmalloc_array(n, sizeof(obj), GFP_KERNEL)
#define kzalloc_objs(obj, n)		kcalloc(n, sizeof(obj), GFP_KERNEL)
#define kvzalloc_objs(obj, n)		kvcalloc(n, sizeof(obj), GFP_KERNEL)
#define kvmalloc_objs(obj, n)		kvmalloc_array(n, sizeof(obj), GFP_KERNEL)
#endif
EOF


# Test BIT_U64 exists
try_compile HAVE_6_16_bit_u64 << 'EOF'
#include <linux/bits.h>
int main(void)
{
	uint64_t a = BIT_U64(1);
	return 0;
}
EOF
cat >> "$OUT" <<'EOF'
#ifndef HAVE_6_16_bit_u64
#define BIT_U64(n)		BIT_ULL(n)
#define GENMASK_U64(m, n)	GENMASK_ULL(m, n)
#endif
EOF

# Test amd_pmf_get_npu_data exists
try_compile HAVE_7_0_amd_pmf_get_npu_data << 'EOF'
#include <linux/module.h>
#include <linux/amd-pmf-io.h>
int main(void)
{
	MODULE_IMPORT_NS("AMD_PMF");

	struct amd_pmf_npu_metrics info;
	int ret = amd_pmf_get_npu_data(&info);
	return 0;
}
EOF

# Test struct amd_pmf_npu_metrics has npu_temp field (7.2+ M80H series)
try_compile HAVE_7_2_amd_pmf_npu_metrics_npu_temp << 'EOF'
#include <linux/module.h>
#include <linux/amd-pmf-io.h>
int main(void)
{
	MODULE_IMPORT_NS("AMD_PMF");

	struct amd_pmf_npu_metrics info;
	info.npu_temp = 0;
	return 0;
}
EOF

#Test drm_fdinfo_print_size exists
try_compile HAVE_6_14_drm_fdinfo_print_size << 'EOF'
#include <drm/drm_file.h>
int main(void)
{
	struct drm_printer *p = NULL;
	drm_fdinfo_print_size(p, NULL, NULL, NULL, 0);
}
EOF
cat >> "$OUT" <<'EOF'
#ifndef HAVE_6_14_drm_fdinfo_print_size
#define drm_fdinfo_print_size(p, prefix, stat, region, sz)		\
	drm_printf(p, "%s-%s-%s:\t%llu KiB\n", prefix, stat, region,	\
	(u64)(sz) / 1024)
#endif
EOF

#Test drm_gem_shmem_put_pages_locked exists
try_compile HAVE_6_16_drm_gem_shmem_put_pages_locked << 'EOF'
#include <drm/drm_gem_shmem_helper.h>
int main(void)
{
	struct drm_gem_shmem_object *p = NULL;
	drm_gem_shmem_put_pages_locked(p);
}
EOF
cat >> "$OUT" <<'EOF'
#ifndef HAVE_6_16_drm_gem_shmem_put_pages_locked
#define drm_gem_shmem_put_pages_locked drm_gem_shmem_put_pages
#endif
EOF

#Test shmem->pages_use_count type
try_compile HAVE_6_16_shmem_pages_use_count_refcnt << 'EOF'
#include <drm/drm_gem_shmem_helper.h>
int main(void)
{
	struct drm_gem_shmem_object shmem;
	refcount_inc_not_zero(&shmem.pages_use_count);
}
EOF

#Test drmm_alloc_ordered_workqueue exists
try_compile HAVE_6_15_drmm_alloc_ordered_workqueue << 'EOF'
#include <drm/drm_managed.h>
int main(void)
{
	struct drm_device *dev = NULL;
	drmm_alloc_ordered_workqueue(dev, "test", 0);
}
EOF
cat >> "$OUT" << 'EOF'
#ifndef HAVE_6_15_drmm_alloc_ordered_workqueue
#include <drm/drm_device.h>
#include <linux/workqueue.h>
static inline void __drmm_workqueue_release(struct drm_device *device, void *res)
{
	struct workqueue_struct *wq = res;

	destroy_workqueue(wq);
}

#define drmm_alloc_ordered_workqueue(dev, fmt, flags, args...)					\
	({											\
		struct workqueue_struct *wq = alloc_ordered_workqueue(fmt, flags, ##args);	\
		wq ? ({										\
			int ret = drmm_add_action_or_reset(dev, __drmm_workqueue_release, wq);	\
			ret ? ERR_PTR(ret) : wq;						\
		}) :										\
			wq;									\
	})
#endif
EOF

# ---- Header trailer ----------------------------------------------------

cat >> "$OUT" <<EOF

#endif /* AMDXDNA_CONFIG_KERNEL_H */
EOF
