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

#include "amdxdna_gem.h"
#include "amdxdna_pci_drv.h"
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
	if (abo->mem.nr_pages)
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

struct amdxdna_gem_obj *amdxdna_alloc_ubuf_bo(struct amdxdna_client *client,
					      u32 num_entries, void __user *va_entries)
{
	struct amdxdna_dev *xdna = client->xdna;
	unsigned long lock_limit, new_pinned;
	struct amdxdna_drm_va_entry *va_ent;
	struct amdxdna_gem_obj *abo;
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

	for (i = 0; i < num_entries; i++) {
		npages = va_ent[i].len >> PAGE_SHIFT;

		ret = pin_user_pages(va_ent[i].vaddr, npages,
				     FOLL_WRITE | FOLL_LONGTERM,
				     &abo->mem.pages[abo->mem.nr_pages]);
		if (ret >= 0) {
			abo->mem.nr_pages += ret;
			if (ret != npages) {
				XDNA_ERR(xdna, "Partially pinned pages %ld/%ld", ret, npages);
				ret = -ENOMEM;
				break;
			}
		} else {
			XDNA_ERR(xdna, "Failed to pin pages ret %ld", ret);
			break;
		}
	}

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
