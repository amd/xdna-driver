// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/kernel.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/kstrtox.h>
#include <linux/of_reserved_mem.h>
#include <linux/string.h>
#include "amdxdna_drm.h"
#include "amdxdna_gem.h"
#include "amdxdna_cma_buf.h"

struct amdxdna_cmabuf_priv {
	struct device *dev;
	dma_addr_t dma_addr;
	void *cpu_addr;
	size_t size;
	bool cacheable;
};

static struct sg_table *
amdxdna_cmabuf_map(struct dma_buf_attachment *attach,
		   enum dma_data_direction dir)
{
	struct amdxdna_cmabuf_priv *cbuf = attach->dmabuf->priv;
	struct scatterlist *sg;
	struct sg_table *sgt;
	int ret;

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	sg = kzalloc(sizeof(*sg), GFP_KERNEL);
	if (!sg) {
		ret = -ENOMEM;
		goto free_sgt;
	}

	sg_init_table(sg, 1);
	/*
	 * Map against cbuf->dev (the producer that allocated this CMA
	 * region), not attach->dev (the importer).  The bus address
	 * lives in the producer's DMA address space and its mask matches
	 * the region that backed it: e.g. an "app-bank<N>" child has a
	 * 64-bit mask while the parent xdna platform device is pinned
	 * to 32-bit so future "rpu-cma" allocations stay below 4 GB.
	 *
	 * On the dma-buf import path used by amdxdna_drm_create_share_bo()
	 * the importer is drm_dev->dev = the parent xdna platform device,
	 * which would (correctly) reject a 64-bit app-bank address
	 * against its 32-bit mask.  Mapping against the producer is the
	 * tightest invariant: it asserts that the device which actually
	 * owns the page can reach it, which is also what the AIE shim
	 * DMA ultimately uses on no-IOMMU platforms.
	 */
	sg_dma_address(sg) = dma_map_resource(cbuf->dev, cbuf->dma_addr,
					      cbuf->size, dir,
					      DMA_ATTR_SKIP_CPU_SYNC);
	ret = dma_mapping_error(cbuf->dev, sg->dma_address);
	if (ret)
		goto free_sg;

	sg_assign_page(sg, NULL);
	sg->offset = 0;
	sg_dma_len(sg) = cbuf->size;
	sgt->orig_nents = 1;
	sgt->nents = sgt->orig_nents;
	sgt->sgl = sg;

	return sgt;

free_sg:
	kfree(sg);
free_sgt:
	kfree(sgt);
	return ERR_PTR(ret);
}

static void amdxdna_cmabuf_unmap(struct dma_buf_attachment *attach,
				 struct sg_table *sgt,
				 enum dma_data_direction dir)
{
	struct amdxdna_cmabuf_priv *cbuf = attach->dmabuf->priv;
	struct scatterlist *sg = sgt->sgl;

	/* Pair with cbuf->dev used in amdxdna_cmabuf_map() above. */
	dma_unmap_resource(cbuf->dev, sg_dma_address(sg), sg_dma_len(sg),
			   dir, DMA_ATTR_SKIP_CPU_SYNC);
	kfree(sg);
	kfree(sgt);
}

static void amdxdna_cmabuf_free(struct device *dev, void *cpu_addr,
				dma_addr_t dma_addr, size_t size,
				bool cacheable)
{
	if (cacheable)
		dma_free_wc(dev, size, cpu_addr, dma_addr);
	else
		dma_free_coherent(dev, size, cpu_addr, dma_addr);
}

static void amdxdna_cmabuf_release(struct dma_buf *dbuf)
{
	struct amdxdna_cmabuf_priv *cmabuf = dbuf->priv;

	if (!cmabuf)
		return;
	amdxdna_cmabuf_free(cmabuf->dev, cmabuf->cpu_addr, cmabuf->dma_addr,
			    cmabuf->size, cmabuf->cacheable);
	kfree(cmabuf);
	dbuf->priv = NULL;
}

static int amdxdna_cmabuf_mmap(struct dma_buf *dbuf, struct vm_area_struct *vma)
{
	struct amdxdna_cmabuf_priv *cmabuf = dbuf->priv;
	size_t size = vma->vm_end - vma->vm_start;
	unsigned long vm_pgoff;
	int ret;

	if (size > cmabuf->size)
		return -EINVAL;

	vm_pgoff = vma->vm_pgoff;
	/* clear the vm_pgoff to avoid dma_buf_ops.mmap failure */
	vma->vm_pgoff = 0;

	vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);

	if (cmabuf->cacheable)
		ret = dma_mmap_wc(cmabuf->dev, vma,
				  cmabuf->cpu_addr,
				  cmabuf->dma_addr,
				  cmabuf->size);
	else
		ret = dma_mmap_coherent(cmabuf->dev, vma,
					cmabuf->cpu_addr,
					cmabuf->dma_addr,
					cmabuf->size);

	vma->vm_pgoff = vm_pgoff;

	return ret;
}

static int amdxdna_cmabuf_vmap(struct dma_buf *dbuf, struct iosys_map *map)
{
	struct amdxdna_cmabuf_priv *cmabuf = dbuf->priv;

	iosys_map_set_vaddr(map, cmabuf->cpu_addr);

	return 0;
}

static const struct dma_buf_ops amdxdna_cmabuf_dmabuf_ops = {
	.map_dma_buf = amdxdna_cmabuf_map,
	.unmap_dma_buf = amdxdna_cmabuf_unmap,
	.release = amdxdna_cmabuf_release,
	.mmap = amdxdna_cmabuf_mmap,
	.vmap = amdxdna_cmabuf_vmap,
};

static struct dma_buf *amdxdna_get_cma_buf(struct amdxdna_dev *xdna,
					   struct device *dev,
					   size_t size, bool cacheable)
{
	struct amdxdna_cmabuf_priv *cmabuf;
	struct dma_buf *dbuf;
	dma_addr_t dma_addr;
	void *cpu_addr;
	int ret;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	cmabuf = kzalloc(sizeof(*cmabuf), GFP_KERNEL);
	if (!cmabuf)
		return ERR_PTR(-ENOMEM);

	size = PAGE_ALIGN(size);

	if (cacheable)
		cpu_addr = dma_alloc_wc(dev, size, &dma_addr, GFP_KERNEL);
	else
		cpu_addr = dma_alloc_coherent(dev, size, &dma_addr, GFP_KERNEL);
	if (!cpu_addr) {
		XDNA_DBG(xdna,
			 "CMA alloc failed on %s: size 0x%zx cacheable %d",
			 dev_name(dev), size, cacheable);
		ret = -ENOMEM;
		goto free_cmabuf;
	}

	cmabuf->dev = dev;
	cmabuf->cpu_addr = cpu_addr;
	cmabuf->dma_addr = dma_addr;
	cmabuf->size = size;
	cmabuf->cacheable = cacheable;

	exp_info.size = size;
	exp_info.ops = &amdxdna_cmabuf_dmabuf_ops;
	exp_info.priv = cmabuf;
	exp_info.flags = O_RDWR;

	dbuf = dma_buf_export(&exp_info);
	if (IS_ERR(dbuf)) {
		ret = PTR_ERR(dbuf);
		goto free_dma;
	}

	XDNA_DBG(xdna,
		 "CMA alloc on %s: dma_addr 0x%llx size 0x%zx cacheable %d",
		 dev_name(dev), (u64)dma_addr, size, cacheable);

	return dbuf;

free_dma:
	amdxdna_cmabuf_free(dev, cpu_addr, dma_addr, size, cacheable);
free_cmabuf:
	kfree(cmabuf);
	return ERR_PTR(ret);
}

bool amdxdna_use_cma(void)
{
#if defined(CONFIG_CMA) && !defined(CONFIG_X86_64) && !defined(CONFIG_X86)
	return true;
#else
	return false;
#endif
}

int amdxdna_cma_sync_bo(struct amdxdna_gem_obj *abo, u64 offset, u64 size,
			enum dma_data_direction dir)
{
	struct amdxdna_cmabuf_priv *cbuf;
	struct dma_buf *dbuf = abo->dma_buf;
	dma_addr_t bus_addr;

	/*
	 * Only operate on BOs that came from our own CMA exporter.  For
	 * everything else (foreign dma_buf imports, shmem, etc.) the
	 * caller must fall back to whatever generic flush path applies.
	 */
	if (!dbuf || dbuf->ops != &amdxdna_cmabuf_dmabuf_ops)
		return -ENODEV;

	cbuf = dbuf->priv;
	if (!cbuf)
		return -ENODEV;

	if (!size)
		return 0;

	bus_addr = cbuf->dma_addr + offset;

	/*
	 * Sync against cbuf->dev (the producer that allocated this CMA
	 * region), not the importer.  The bus address lives in the
	 * producer's DMA address space and only the producer's
	 * dma-ranges yield the correct phys for arch_sync_dma_for_*().
	 * This mirrors what amdxdna_cmabuf_map() does for
	 * dma_map_resource() for the same reason.
	 */
	switch (dir) {
	case DMA_TO_DEVICE:
		/* CPU is producer; clean dirty lines so FW sees writes. */
		dma_sync_single_for_device(cbuf->dev, bus_addr, size,
					   DMA_TO_DEVICE);
		break;
	case DMA_FROM_DEVICE:
		/* FW is producer; invalidate stale CPU lines before read. */
		dma_sync_single_for_cpu(cbuf->dev, bus_addr, size,
					DMA_FROM_DEVICE);
		break;
	case DMA_BIDIRECTIONAL:
	default:
		/*
		 * Direction unspecified / both: a single
		 * _for_device(BIDIRECTIONAL) does clean + invalidate on
		 * arm64 (__dma_flush_area), which satisfies both
		 * "CPU just wrote, FW will read" and "FW will write,
		 * CPU will read" over [offset, offset+size).
		 */
		dma_sync_single_for_device(cbuf->dev, bus_addr, size,
					   DMA_BIDIRECTIONAL);
		break;
	}

	return 0;
}

static bool get_cacheable_flag(u64 flags)
{
	return (flags & AMDXDNA_BO_FLAGS_CACHEABLE) != 0;
}

/**
 * amdxdna_get_cma_buf_with_fallback - Allocate CMA buffer with region fallback
 * @region_devs: Array of device pointers for "app-bank<N>" CMA regions
 *               (NULL = not initialized).  Bit N in the @flags low byte
 *               selects @region_devs[N].
 * @max_regions: Maximum number of entries in @region_devs.
 * @fallback_dev: Device to use when @flags requests no banks, or when
 *                every requested bank is unavailable.  This is the
 *                platform device itself, bound to the "rpu-cma" region
 *                (or to the system default CMA when no "rpu-cma" is
 *                configured).  Allocations from this device land in
 *                the lower 4 GB on T20-style platforms where the
 *                parent has a 32-bit DMA mask.
 * @size: Size of buffer to allocate.
 * @flags: Cacheable bit (BIT(24)) and region bitmap (low 8 bits).
 *
 * Honors the bank bitmap exactly:
 *
 *   • Each bit set in the low 8 bits is tried, in ascending bit order,
 *     against the matching @region_devs[] entry.  First success wins.
 *   • If no bit is set in the low byte, or every requested bank is
 *     unavailable / OOM, fall back to @fallback_dev.
 *
 * Note: callers that want user-mode BOs to default to an AIE bank
 * should set the appropriate bit in @flags before calling.  The
 * AMDXDNA_CREATE_BO ioctl handler does this in
 * amdxdna_drm_create_bo_ioctl(): if userspace did not request any
 * bank, the kernel sets BIT(0) so the BO lands in app-bank0 and the
 * fallback is taken only when no app-bank0 is declared.
 *
 * Return: dma_buf pointer on success, ERR_PTR on failure.
 */
struct dma_buf *amdxdna_get_cma_buf_with_fallback(struct amdxdna_dev *xdna,
						  struct device *const *region_devs,
						  int max_regions,
						  struct device *fallback_dev,
						  size_t size, u64 flags)
{
	struct dma_buf *dma_buf;
	bool cacheable;
	u32 mem_bitmap;
	unsigned int i;

	cacheable = get_cacheable_flag(flags);
	mem_bitmap = (u32)(flags & 0xFFULL);

	for (i = 0; i < max_regions; i++) {
		if ((mem_bitmap & (1U << i)) && region_devs[i]) {
			dma_buf = amdxdna_get_cma_buf(xdna, region_devs[i],
						      size, cacheable);
			if (!IS_ERR(dma_buf))
				return dma_buf;
		}
	}

	/*
	 * No bank requested, or every requested bank failed.
	 * Fall back to the parent device (rpu-cma / system default CMA).
	 */
	XDNA_DBG(xdna, "Falling back to parent dev %s (flags 0x%llx, size 0x%zx)",
		 dev_name(fallback_dev), flags, size);
	return amdxdna_get_cma_buf(xdna, fallback_dev, size, cacheable);
}

static void amdxdna_cma_device_release(struct device *dev)
{
	kfree(dev);
}

#define AMDXDNA_RPU_CMA_NAME		"rpu-cma"
#define AMDXDNA_APP_BANK_PREFIX		"app-bank"
#define AMDXDNA_APP_BANK_PREFIX_LEN	(sizeof(AMDXDNA_APP_BANK_PREFIX) - 1)

/*
 * Parse "app-bank<N>" -> N.  Returns >= 0 on success, -1 if @name is not
 * an app-bank entry or the index is out of range.  The trailing digits
 * must form a complete unsigned decimal with no leading sign or
 * whitespace.
 */
static int amdxdna_parse_app_bank_index(const char *name)
{
	unsigned int idx;

	if (strncmp(name, AMDXDNA_APP_BANK_PREFIX,
		    AMDXDNA_APP_BANK_PREFIX_LEN))
		return -1;

	if (kstrtouint(name + AMDXDNA_APP_BANK_PREFIX_LEN, 10, &idx))
		return -1;

	if (idx >= MAX_MEM_REGIONS)
		return -1;

	return (int)idx;
}

static int amdxdna_bind_app_bank(struct amdxdna_dev *xdna,
				 struct device_node *mem_np, int phandle_idx,
				 int bank)
{
	struct device *parent_dev = xdna->ddev.dev;
	struct device *child_dev;
	int ret;

	if (xdna->cma_region_devs[bank]) {
		XDNA_ERR(xdna,
			 "Duplicate " AMDXDNA_APP_BANK_PREFIX "%d entry (idx %d)",
			 bank, phandle_idx);
		return -EINVAL;
	}

	child_dev = kzalloc(sizeof(*child_dev), GFP_KERNEL);
	if (!child_dev)
		return -ENOMEM;

	device_initialize(child_dev);
	child_dev->parent = parent_dev;
	child_dev->of_node = mem_np;
	child_dev->coherent_dma_mask = DMA_BIT_MASK(64);
	child_dev->dma_mask = &child_dev->coherent_dma_mask;
	child_dev->release = amdxdna_cma_device_release;

	ret = dev_set_name(child_dev, "amdxdna-app-bank%d", bank);
	if (ret)
		goto put_dev;

	ret = of_reserved_mem_device_init_by_idx(child_dev, mem_np, phandle_idx);
	if (ret) {
		XDNA_ERR(xdna,
			 "Failed to init " AMDXDNA_APP_BANK_PREFIX "%d (idx %d): %d",
			 bank, phandle_idx, ret);
		goto put_dev;
	}

	xdna->cma_region_devs[bank] = child_dev;
	XDNA_INFO(xdna, AMDXDNA_APP_BANK_PREFIX "%d bound (idx %d)",
		  bank, phandle_idx);
	return 0;

put_dev:
	put_device(child_dev);
	return ret;
}

/**
 * amdxdna_cma_region_init - Bind named CMA regions for the xdna device
 * @xdna: XDNA device
 * @mem_np: DT node carrying "memory-region" / "memory-region-names"
 *
 * The DT node identifies its CMA pools by name.  Two roles are defined:
 *
 *   "rpu-cma"     - bound directly to xdna->ddev.dev (the platform
 *                   device) so that dma_alloc_coherent() on the device
 *                   pulls from this pool.  Used by kernel-side
 *                   firmware-visible mgmt buffers (async event ring,
 *                   FW DRAM log, FW event-trace ring, mpnpufw work
 *                   buffer) and as the last-resort fallback for BO
 *                   allocations.  On platforms where the remote
 *                   firmware (e.g. RPU) can only address the lower
 *                   4 GB of physical memory, this region MUST live in
 *                   that window.  Optional — if absent, the parent
 *                   device retains its DT-/system-default CMA pool
 *                   (and management buffers come from there).
 *
 *   "app-bank<N>" - 0-indexed, bound to a child device with a 64-bit
 *                   DMA mask and stored in cma_region_devs[N].  These
 *                   are the user-visible AIE banks and are addressed
 *                   via the low 8 bits of the BO `flags` field
 *                   (bit N -> bank N).  User-mode BO ioctls default to
 *                   bank 0 when no bit is set.
 *
 * Return: 0 on success (including when no recognized regions are
 *         present), negative errno on failure.  Bank indices must be
 *         unique and < MAX_MEM_REGIONS; "rpu-cma" must appear at most
 *         once.  Any unknown name in memory-region-names is silently
 *         ignored so the binding can be extended later without
 *         breaking older drivers.
 */
int amdxdna_cma_region_init(struct amdxdna_dev *xdna, struct device_node *mem_np)
{
	struct device *parent_dev = xdna->ddev.dev;
	bool rpu_bound = false;
	int num_regions;
	int ret;
	int i;

	num_regions = of_property_count_strings(mem_np, "memory-region-names");
	if (num_regions <= 0)
		return 0;

	for (i = 0; i < num_regions; i++) {
		const char *name;
		int bank;

		ret = of_property_read_string_index(mem_np,
						    "memory-region-names",
						    i, &name);
		if (ret) {
			XDNA_ERR(xdna,
				 "Failed to read memory-region-names[%d]: %d",
				 i, ret);
			goto cleanup;
		}

		if (!strcmp(name, AMDXDNA_RPU_CMA_NAME)) {
			if (rpu_bound) {
				XDNA_ERR(xdna,
					 "Duplicate \"" AMDXDNA_RPU_CMA_NAME
					 "\" entry (idx %d)", i);
				ret = -EINVAL;
				goto cleanup;
			}

			ret = of_reserved_mem_device_init_by_idx(parent_dev,
								 mem_np, i);
			if (ret) {
				XDNA_ERR(xdna,
					 "Failed to bind \"" AMDXDNA_RPU_CMA_NAME
					 "\" (idx %d): %d", i, ret);
				goto cleanup;
			}
			XDNA_INFO(xdna, "\"" AMDXDNA_RPU_CMA_NAME
				  "\" bound to parent (idx %d)", i);
			rpu_bound = true;
			xdna->rpu_cma_bound = true;
			continue;
		}

		bank = amdxdna_parse_app_bank_index(name);
		if (bank < 0) {
			XDNA_DBG(xdna,
				 "Skipping unknown memory-region-name \"%s\" (idx %d)",
				 name, i);
			continue;
		}

		ret = amdxdna_bind_app_bank(xdna, mem_np, i, bank);
		if (ret)
			goto cleanup;
	}

	return 0;

cleanup:
	amdxdna_cma_region_fini(xdna);
	return ret;
}

void amdxdna_cma_region_fini(struct amdxdna_dev *xdna)
{
	int i;

	for (i = 0; i < MAX_MEM_REGIONS; i++) {
		struct device *dev = xdna->cma_region_devs[i];

		if (dev) {
			of_reserved_mem_device_release(dev);
			put_device(dev);
			xdna->cma_region_devs[i] = NULL;
		}
	}

	/*
	 * Release the "rpu-cma" region bound to the parent device.
	 * Safe to call unconditionally: if no rpu-cma was bound this is
	 * a no-op on a device with no reserved-memory binding.
	 */
	of_reserved_mem_device_release(xdna->ddev.dev);
	xdna->rpu_cma_bound = false;
}
