// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_device.h>
#include <drm/drm_print.h>
#include <linux/iosys-map.h>
#include <linux/limits.h>
#include <linux/overflow.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <xen/xen.h>

#include "amdxdna_gem.h"
#include "amdxdna_drv.h"
#include "amdxdna_ubuf.h"

static void amdxdna_ubuf_unmap_dma(struct amdxdna_gem_obj *abo)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);

	if (!abo->mem.sgt)
		return;

	dma_unmap_sgtable(xdna->ddev.dev, abo->mem.sgt, DMA_BIDIRECTIONAL, 0);
	sg_free_table(abo->mem.sgt);
	kfree(abo->mem.sgt);
}

static void amdxdna_gem_ubuf_obj_free(struct drm_gem_object *gobj)
{
	struct amdxdna_dev *xdna = to_xdna_dev(gobj->dev);
	struct amdxdna_gem_obj *abo = to_xdna_obj(gobj);

	amdxdna_hmm_unregister(abo, NULL, 0, 0);
	flush_workqueue(xdna->notifier_wq);

	amdxdna_dma_unmap_bo(xdna, abo);
	amdxdna_ubuf_unmap_dma(abo);
	/* Foreign pages are borrowed from the Xen mapping; never unpin them. */
	if (abo->mem.nr_pages && !abo->mem.foreign)
		unpin_user_pages(abo->mem.pages, abo->mem.nr_pages);
	atomic64_sub(abo->mem.size >> PAGE_SHIFT, &abo->mem.mm->pinned_vm);
	kvfree(abo->mem.pages);
	mmdrop(abo->mem.mm);
	drm_gem_object_release(gobj);
	amdxdna_gem_destroy_obj(abo);
}

static struct dma_buf *amdxdna_gem_ubuf_obj_export(struct drm_gem_object *gobj, int flags)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static int amdxdna_gem_ubuf_obj_vmap(struct drm_gem_object *obj, struct iosys_map *map)
{
	struct amdxdna_gem_obj *abo = to_xdna_obj(obj);
	void *kva;

	if (abo->mem.nr_pages > UINT_MAX)
		return -EINVAL;

	kva = vmap(abo->mem.pages, (unsigned int)abo->mem.nr_pages, VM_MAP, PAGE_KERNEL);
	if (!kva)
		return -ENOMEM;

	iosys_map_set_vaddr(map, kva);
	return 0;
}

static void amdxdna_gem_ubuf_obj_vunmap(struct drm_gem_object *obj, struct iosys_map *map)
{
	if (map->vaddr)
		vunmap(map->vaddr);

	iosys_map_clear(map);
}

static const struct drm_gem_object_funcs amdxdna_gem_ubuf_obj_funcs = {
	.free = amdxdna_gem_ubuf_obj_free,
	.open = amdxdna_gem_obj_open,
	.close = amdxdna_gem_obj_close,
	.export = amdxdna_gem_ubuf_obj_export,
	.vmap = amdxdna_gem_ubuf_obj_vmap,
	.vunmap = amdxdna_gem_ubuf_obj_vunmap,
};

static struct vm_area_struct *amdxdna_ubuf_find_vma(struct amdxdna_drm_va_entry *va_ent)
{
	struct vm_area_struct *vma;

	vma = find_vma(current->mm, va_ent->vaddr);
	if (!vma || vma->vm_start > va_ent->vaddr ||
	    vma->vm_end - va_ent->vaddr < va_ent->len)
		return NULL;

	return vma;
}

static void amdxdna_ubuf_check_readonly(struct amdxdna_gem_obj *abo,
					struct amdxdna_drm_va_entry *va_ent,
					u32 num_entries)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	struct vm_area_struct *vma;
	int i;

	for (i = 0; i < num_entries; i++) {
		vma = amdxdna_ubuf_find_vma(&va_ent[i]);
		if (!vma) {
			XDNA_DBG(xdna, "Invalid entry vaddr %llx, len %llx",
				 va_ent[i].vaddr, va_ent[i].len);
			return;
		}
		if (vma->vm_flags & (VM_WRITE | VM_MAYWRITE))
			return;
	}
	abo->readonly = true;
}

static int amdxdna_ubuf_hmm_register(struct amdxdna_gem_obj *abo,
				     struct amdxdna_drm_va_entry *va_ent,
				     u32 num_entries)
{
	int i, ret = 0;

	mmap_write_lock(current->mm);

	for (i = 0; i < num_entries; i++) {
		ret = amdxdna_hmm_register(abo, current->mm, va_ent[i].vaddr, va_ent[i].len);
		if (ret)
			break;
	}

	mmap_write_unlock(current->mm);

	return ret;
}

/*
 * Xen foreign guest memory (privcmd MMAPBATCH) is mapped VM_IO|VM_PFNMAP, so
 * pin_user_pages() returns -EFAULT. On an auto-translated (PVH) dom0 privcmd
 * stores the local page array backing the foreign frames in
 * vma->vm_private_data (ZONE_DEVICE pages from xen_alloc_unpopulated_pages).
 *
 * Detect this heuristically from public VMA state: we cannot compare
 * vma->vm_ops against privcmd's (it is static in drivers/xen). A value of
 * (void *)1 is privcmd's PRIV_VMA_LOCKED marker (PV dom0, no local pages).
 * On success returns the page array and its length in @count.
 */
static struct page **amdxdna_xen_foreign_pages(struct vm_area_struct *vma,
					       unsigned long *count)
{
	struct page **pages;

	if (!xen_domain())
		return NULL;
	if ((vma->vm_flags & (VM_IO | VM_PFNMAP)) != (VM_IO | VM_PFNMAP))
		return NULL;

	pages = vma->vm_private_data;
	if (!pages || pages == (struct page **)1)
		return NULL;

	*count = vma_pages(vma);
	return pages;
}

/*
 * Populate abo->mem.pages for one VA entry, under mmap_read_lock. When the BO
 * is a Xen foreign (privcmd) mapping its pages can't be pinned, so borrow them
 * from the privcmd VMA's local page array; otherwise pin_user_pages() them.
 * The mode is fixed for the whole BO (see abo->mem.foreign) because free is
 * all-or-nothing, so a foreign BO validates that every entry is foreign too.
 * Returns the number of pages added, or a negative errno.
 */
static long amdxdna_ubuf_get_pages(struct amdxdna_gem_obj *abo,
				   struct amdxdna_drm_va_entry *va_ent)
{
	struct amdxdna_dev *xdna = to_xdna_dev(to_gobj(abo)->dev);
	unsigned long npages = va_ent->len >> PAGE_SHIFT;
	struct vm_area_struct *vma;
	long ret;

	if (abo->mem.foreign) {
		unsigned long fcount, off, j;
		struct page **fpages;

		vma = amdxdna_ubuf_find_vma(va_ent);
		fpages = vma ? amdxdna_xen_foreign_pages(vma, &fcount) : NULL;
		if (!fpages) {
			XDNA_ERR(xdna, "Entry vaddr %llx is not a foreign mapping",
				 va_ent->vaddr);
			return -EINVAL;
		}

		off = (va_ent->vaddr - vma->vm_start) >> PAGE_SHIFT;
		if (off + npages > fcount) {
			XDNA_ERR(xdna, "Foreign entry out of range %lu+%lu > %lu",
				 off, npages, fcount);
			return -EINVAL;
		}

		for (j = 0; j < npages; j++)
			abo->mem.pages[abo->mem.nr_pages++] = fpages[off + j];

		return npages;
	}

	/*
	 * Non-foreign entries take the normal pin path. In particular, when a
	 * Xen guest grants pages to this (dom0) domain and they are mapped via
	 * gntdev, the mapping is VM_MIXEDMAP backed by local struct pages -- i.e.
	 * normal, pinnable pages -- unlike privcmd foreign (VM_IO|VM_PFNMAP)
	 * mappings, which have no pinnable struct page and are borrowed above.
	 *
	 * Caveat for grant pages: the FOLL_LONGTERM pin only holds a reference on
	 * the local (dom0) struct page, not on the grant itself. The grant is
	 * owned by the guest; if the guest revokes it (or gntdev unmaps) while
	 * this BO is alive, the local page's p2m/backing machine frame changes,
	 * but the device's IOMMU mapping (amdxdna_dma_map_bo() programs it from
	 * the page's physical address) still points at the old frame. The device
	 * then DMAs to a stale/reused machine frame -- silent corruption. There
	 * is no notifier here to catch revocation, so the BO must be destroyed
	 * before the grant is revoked; callers must order teardown accordingly.
	 */
	ret = pin_user_pages(va_ent->vaddr, npages,
			     (abo->readonly ? 0 : FOLL_WRITE) | FOLL_LONGTERM,
			     &abo->mem.pages[abo->mem.nr_pages]);
	if (ret < 0) {
		XDNA_ERR(xdna, "Failed to pin pages ret %ld", ret);
		return ret;
	}

	abo->mem.nr_pages += ret;
	if (ret != npages) {
		XDNA_ERR(xdna, "Partially pinned pages %ld/%ld", ret, npages);
		return -ENOMEM;
	}

	return ret;
}

struct amdxdna_gem_obj *amdxdna_alloc_ubuf_bo(struct amdxdna_client *client,
					      u32 num_entries, void __user *va_entries)
{
	struct amdxdna_dev *xdna = client->xdna;
	unsigned long lock_limit, new_pinned;
	struct amdxdna_drm_va_entry *va_ent;
	struct amdxdna_gem_obj *abo;
	struct vm_area_struct *vma;
	unsigned long fcount = 0;
	unsigned long npages;
	bool need_contig;
	size_t bufsize;
	long ret;
	int i;

	if (!can_do_mlock())
		return ERR_PTR(-EPERM);

	va_ent = kvzalloc_objs(*va_ent, num_entries);
	if (!va_ent)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(va_ent, va_entries, sizeof(*va_ent) * num_entries)) {
		XDNA_DBG(xdna, "Access va entries failed");
		ret = -EINVAL;
		goto free_ent;
	}

	/*
	 * With an IOMMU domain the scattered pages are mapped to a single
	 * contiguous device IOVA (iommu_map_sgtable), so the entries need not be
	 * contiguous in user VA. Without one (PASID/SVA or PA mode) the device
	 * addresses the BO at its user VA and the BO records only the first
	 * entry's VA, so require the entries to describe one contiguous VA range.
	 */
	need_contig = !amdxdna_iova_on(xdna);

	for (i = 0, bufsize = 0; i < num_entries; i++) {
		if (!IS_ALIGNED(va_ent[i].vaddr, PAGE_SIZE) ||
		    !IS_ALIGNED(va_ent[i].len, PAGE_SIZE) ||
		    !va_ent[i].len) {
			XDNA_ERR(xdna, "Invalid address or len %llx, %llx",
				 va_ent[i].vaddr, va_ent[i].len);
			ret = -EINVAL;
			goto free_ent;
		}

		if (need_contig && i &&
		    va_ent[i].vaddr != va_ent[i - 1].vaddr + va_ent[i - 1].len) {
			XDNA_ERR(xdna, "Non-contiguous va entry %d, %llx after %llx+%llx",
				 i, va_ent[i].vaddr, va_ent[i - 1].vaddr,
				 va_ent[i - 1].len);
			ret = -EINVAL;
			goto free_ent;
		}

		if (check_add_overflow(bufsize, va_ent[i].len, &bufsize)) {
			ret = -EINVAL;
			goto free_ent;
		}
	}

	abo = amdxdna_gem_create_obj(&xdna->ddev, bufsize);
	if (IS_ERR(abo)) {
		ret = PTR_ERR(abo);
		goto free_ent;
	}

	abo->client = client;
	abo->mem.mm = current->mm;
	abo->type = AMDXDNA_BO_SHARE;
	mmgrab(abo->mem.mm);
	to_gobj(abo)->funcs = &amdxdna_gem_ubuf_obj_funcs;
	drm_gem_private_object_init(&xdna->ddev, to_gobj(abo), bufsize);

	npages = bufsize >> PAGE_SHIFT;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	new_pinned = atomic64_add_return(npages, &abo->mem.mm->pinned_vm);
	if (new_pinned > lock_limit && !capable(CAP_IPC_LOCK)) {
		XDNA_DBG(xdna, "New pin %ld, limit %ld, cap %d",
			 new_pinned, lock_limit, capable(CAP_IPC_LOCK));
		ret = -ENOMEM;
		goto put_obj;
	}

	abo->mem.pages = kvmalloc_objs(*abo->mem.pages, npages);
	if (!abo->mem.pages) {
		ret = -ENOMEM;
		goto put_obj;
	}

	mmap_read_lock(current->mm);
	amdxdna_ubuf_check_readonly(abo, va_ent, num_entries);

	/*
	 * Xen foreign (privcmd) mappings are VM_IO|VM_PFNMAP and can't be
	 * pinned. Decide the mode once from the first entry so the whole BO is
	 * uniformly borrowed or pinned (free is all-or-nothing). Grant (gntdev)
	 * mappings are VM_MIXEDMAP and take the normal pin path.
	 */
	vma = amdxdna_ubuf_find_vma(&va_ent[0]);
	if (vma && amdxdna_xen_foreign_pages(vma, &fcount))
		abo->mem.foreign = true;

	for (i = 0; i < num_entries; i++) {
		ret = amdxdna_ubuf_get_pages(abo, &va_ent[i]);
		if (ret < 0)
			break;
	}
	mmap_read_unlock(current->mm);

	if (ret < 0)
		goto put_obj;

	ret = amdxdna_ubuf_hmm_register(abo, va_ent, num_entries);
	if (ret)
		goto put_obj;

	kvfree(va_ent);
	return abo;

put_obj:
	drm_gem_object_put(to_gobj(abo));
free_ent:
	kvfree(va_ent);
	return ERR_PTR(ret);
}
