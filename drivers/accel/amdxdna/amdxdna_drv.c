// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 *
 * Bus-agnostic amdxdna core: the DRM driver definition, file operations,
 * client open/close and the shared ioctl handlers. Bus-specific attachment
 * lives in amdxdna_pci_drv.c (PCI) and amdxdna_aux_drv.c (auxiliary bus).
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_accel.h>
#include <drm/drm_drv.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_managed.h>
#include <drm/gpu_scheduler.h>
#include <linux/delay.h>
#include <linux/iommu.h>

#include "aie.h"
#include "amdxdna_cbuf.h"
#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "amdxdna_pci_drv.h"

/*
 * 0.0: Initial version
 * 0.1: Support getting all hardware contexts by DRM_IOCTL_AMDXDNA_GET_ARRAY
 * 0.2: Support getting last error hardware error
 * 0.3: Support firmware debug buffer
 * 0.4: Support getting resource information
 * 0.5: Support getting telemetry data
 * 0.6: Support preemption
 * 0.7: Support getting power and utilization data
 * 0.8: Support BO usage query
 * 0.9: Add new device type AMDXDNA_DEV_TYPE_PF
 * 0.10: Add new device type AMDXDNA_DEV_TYPE_UMQ
 * 0.11: Support AIE coredump
 * 0.12: Add classic device type of NPU3
 * 0.13: Support AIE tile register/memory read/write
 * 0.14: Expose firmware log GET/GET_CONFIG/SET_STATE ioctls and
 *       struct amdxdna_dpt_metadata, _set_dpt_state, _get_dpt_state
 * 0.15: Expose firmware trace GET/GET_CONFIG/SET_STATE ioctls
 */
#define AMDXDNA_DRIVER_MAJOR		0
#define AMDXDNA_DRIVER_MINOR		15

#ifndef AMDXDNA_NPU3A
static int amdxdna_sva_init(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;

	client->sva = iommu_sva_bind_device(xdna->ddev.dev, client->mm);
	if (IS_ERR(client->sva)) {
		XDNA_ERR(xdna, "SVA bind device failed, ret %ld", PTR_ERR(client->sva));
		return PTR_ERR(client->sva);
	}

	client->pasid = iommu_sva_get_pasid(client->sva);
	if (client->pasid == IOMMU_PASID_INVALID) {
		iommu_sva_unbind_device(client->sva);
		client->sva = NULL;
		XDNA_ERR(xdna, "SVA get pasid failed");
		return -ENODEV;
	}

	return 0;
}
#endif

void amdxdna_sva_fini(struct amdxdna_client *client)
{
	if (IS_ERR_OR_NULL(client->sva))
		return;

	iommu_sva_unbind_device(client->sva);
	client->sva = NULL;
	client->pasid = IOMMU_PASID_INVALID;
}

static int amdxdna_drm_open(struct drm_device *ddev, struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(ddev);
	struct amdxdna_client *tmp, *client;
	int ret;

	client = kzalloc_obj(*client);
	if (!client)
		return -ENOMEM;

	ret = init_srcu_struct(&client->hwctx_srcu);
	if (ret)
		goto free_client;

	client->pid = pid_nr(rcu_access_pointer(filp->pid));
	client->xdna = xdna;
	client->pasid = IOMMU_PASID_INVALID;
	client->mm = current->mm;

#ifndef AMDXDNA_NPU3A
	if (!amdxdna_iova_on(xdna)) {
		/* No need to fail open since user may use pa + carveout later. */
		if (amdxdna_sva_init(client)) {
			XDNA_WARN(xdna, "PASID not available for pid %d", client->pid);
			if (!amdxdna_use_carveout(xdna)) {
				XDNA_ERR(xdna, "PASID unavailable and carveout not configured");
				ret = -EINVAL;
				goto cleanup_srcu;
			}
		}
	}
#endif
	mmgrab(client->mm);
	xa_init_flags(&client->hwctx_xa, XA_FLAGS_ALLOC);
	xa_init_flags(&client->dev_heap_xa, XA_FLAGS_ALLOC);
	/* Devices without a managed dev-heap aperture (e.g. PA-mode aie4) leave
	 * dev_heap_max_size at 0; drm_mm_init() BUGs on a zero-sized range.
	 */
	if (xdna->dev_info->dev_heap_max_size)
		drm_mm_init(&client->dev_heap_mm, xdna->dev_info->dev_mem_base,
			    xdna->dev_info->dev_heap_max_size);
	mutex_init(&client->mm_lock);

	mutex_lock(&xdna->client_lock);
	mutex_lock(&xdna->dev_lock);
	amdxdna_for_each_client(xdna, tmp) {
		if (tmp->pid == client->pid) {
			mutex_unlock(&xdna->dev_lock);
			mutex_unlock(&xdna->client_lock);
			XDNA_WARN(xdna, "pid %d already opened the device", client->pid);
			ret = -EBUSY;
			goto fail;
		}
	}
	list_add_tail(&client->node, &xdna->client_list);
	mutex_unlock(&xdna->dev_lock);
	mutex_unlock(&xdna->client_lock);

	filp->driver_priv = client;
	client->filp = filp;

	spin_lock_init(&client->io_stats.lock);

	XDNA_DBG(xdna, "pid %d opened", client->pid);
	return 0;

fail:
	if (xdna->dev_info->dev_heap_max_size)
		drm_mm_takedown(&client->dev_heap_mm);
	xa_destroy(&client->dev_heap_xa);
	xa_destroy(&client->hwctx_xa);
	mutex_destroy(&client->mm_lock);
	mmdrop(client->mm);
	amdxdna_sva_fini(client);
#ifndef AMDXDNA_NPU3A
cleanup_srcu:
#endif
	cleanup_srcu_struct(&client->hwctx_srcu);
free_client:
	kfree(client);
	return ret;
}

void amdxdna_client_cleanup(struct amdxdna_client *client)
{
	struct amdxdna_gem_obj *heap;
	unsigned long heap_id;

	list_del(&client->node);
	amdxdna_hwctx_remove_all(client);
	xa_destroy(&client->hwctx_xa);
	cleanup_srcu_struct(&client->hwctx_srcu);

	xa_for_each(&client->dev_heap_xa, heap_id, heap)
		drm_gem_object_put(to_gobj(heap));
	xa_destroy(&client->dev_heap_xa);
	if (client->xdna->dev_info->dev_heap_max_size)
		drm_mm_takedown(&client->dev_heap_mm);
	mutex_destroy(&client->mm_lock);
	mmdrop(client->mm);
	amdxdna_sva_fini(client);
	kfree(client);
}

static void amdxdna_drm_close(struct drm_device *ddev, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(ddev);

	XDNA_DBG(xdna, "closing pid %d", client->pid);

	mutex_lock(&xdna->client_lock);
	mutex_lock(&xdna->dev_lock);
	amdxdna_client_cleanup(client);
	mutex_unlock(&xdna->dev_lock);
	mutex_unlock(&xdna->client_lock);
}

static int amdxdna_drm_get_info_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_get_info *args = data;
	int ret;

	if (!xdna->dev_info->ops->get_aie_info)
		return -EOPNOTSUPP;

	XDNA_DBG(xdna, "Request parameter %u", args->param);
	mutex_lock(&xdna->dev_lock);
	ret = xdna->dev_info->ops->get_aie_info(client, args);
	mutex_unlock(&xdna->dev_lock);
	return ret;
}

static int amdxdna_drm_get_array_ioctl(struct drm_device *dev, void *data,
				       struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_get_array *args = data;

	if (!xdna->dev_info->ops->get_array)
		return -EOPNOTSUPP;

	if (args->pad || !args->num_element || !args->element_size)
		return -EINVAL;

	/* dev_lock is NOT held across this call. Cases that need it take
	 * it themselves; the FW_LOG watch path uses SRCU instead so that
	 * multiple xrt-smi watchers can sleep concurrently inside
	 * wait_event_interruptible.
	 */
	return xdna->dev_info->ops->get_array(client, args);
}

static int amdxdna_drm_set_state_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_set_state *args = data;
	u32 settle_ms = 0;
	int ret;

	if (!xdna->dev_info->ops->set_aie_state)
		return -EOPNOTSUPP;

	XDNA_DBG(xdna, "Request parameter %u", args->param);
	mutex_lock(&xdna->dev_lock);
	ret = xdna->dev_info->ops->set_aie_state(client, args, &settle_ms);
	mutex_unlock(&xdna->dev_lock);

	/*
	 * Some state changes (e.g. a power-mode override that raises the DPM
	 * level) need time for the NPU clock to ramp. Wait here, after dev_lock
	 * is released, so the settle does not stall other dev_lock operations.
	 */
	if (!ret && settle_ms)
		msleep(settle_ms);

	return ret;
}

static int amdxdna_drm_gem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct drm_file *drm_filp = filp->private_data;
	struct amdxdna_client *client = drm_filp->driver_priv;
	struct amdxdna_dev *xdna = client->xdna;

	if (likely(vma->vm_pgoff >= DRM_FILE_PAGE_OFFSET_START))
		return drm_gem_mmap(filp, vma);

	if (!xdna->dev_info->ops->mmap)
		return -EOPNOTSUPP;

	return xdna->dev_info->ops->mmap(client, vma);
}

static const struct drm_ioctl_desc amdxdna_drm_ioctls[] = {
	/* Context */
	DRM_IOCTL_DEF_DRV(AMDXDNA_CREATE_HWCTX, amdxdna_drm_create_hwctx_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_DESTROY_HWCTX, amdxdna_drm_destroy_hwctx_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_CONFIG_HWCTX, amdxdna_drm_config_hwctx_ioctl, 0),
	/* BO */
	DRM_IOCTL_DEF_DRV(AMDXDNA_CREATE_BO, amdxdna_drm_create_bo_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_GET_BO_INFO, amdxdna_drm_get_bo_info_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_SYNC_BO, amdxdna_drm_sync_bo_ioctl, 0),
	/* Execution */
	DRM_IOCTL_DEF_DRV(AMDXDNA_EXEC_CMD, amdxdna_drm_submit_cmd_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_WAIT_CMD, amdxdna_drm_wait_cmd_ioctl, 0),
	/* AIE hardware */
	DRM_IOCTL_DEF_DRV(AMDXDNA_GET_INFO, amdxdna_drm_get_info_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_GET_ARRAY, amdxdna_drm_get_array_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_SET_STATE, amdxdna_drm_set_state_ioctl, DRM_ROOT_ONLY),
};

static void amdxdna_show_fdinfo(struct drm_printer *p, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	size_t heap_usage, external_usage, internal_usage;
	char *drv_name = filp->minor->dev->driver->name;

	drm_printf(p, "drm-engine-%s:\t%llu ns\n",
		   drv_name, amdxdna_io_stats_busy_time_ns(client));

	mutex_lock(&client->mm_lock);

	heap_usage = client->heap_usage;
	internal_usage = client->total_int_bo_usage;
	external_usage = client->total_bo_usage - internal_usage;

	mutex_unlock(&client->mm_lock);

	/*
	 * Note for driver specific BO memory usage stat.
	 * Total memory in use = amdxdna-internal-alloc + amdxdna-external-alloc, which
	 * includes both imported and created BOs. To avoid double counts, it includes
	 * HEAP BO, but not DEV BO. DEV BO is counted by amdxdna-heap-alloc.
	 */
	drm_fdinfo_print_size(p, drv_name, "heap", "alloc", heap_usage);
	drm_fdinfo_print_size(p, drv_name, "internal", "alloc", internal_usage);
	drm_fdinfo_print_size(p, drv_name, "external", "alloc", external_usage);
	/*
	 * Note for DRM standard BO memory stat.
	 * drm-total-memory counts both DEV BO and HEAP BO. The DEV BO size is double counted.
	 * drm-shared-memory counts BO shared with other processes/devices.
	 */
	drm_show_memory_stats(p, filp);
}

static const struct file_operations amdxdna_fops = {
	.owner		= THIS_MODULE,
	.open		= accel_open,
	.release	= drm_release,
	.unlocked_ioctl	= drm_ioctl,
	.compat_ioctl	= drm_compat_ioctl,
	.poll		= drm_poll,
	.read		= drm_read,
	.llseek		= noop_llseek,
	.mmap		= amdxdna_drm_gem_mmap,
	.show_fdinfo	= drm_show_fdinfo,
#ifdef FOP_UNSIGNED_OFFSET
	.fop_flags	= FOP_UNSIGNED_OFFSET,
#endif
};

const struct drm_driver amdxdna_drm_drv = {
	.driver_features = DRIVER_GEM | DRIVER_COMPUTE_ACCEL |
		DRIVER_SYNCOBJ | DRIVER_SYNCOBJ_TIMELINE,
	.fops = &amdxdna_fops,
	.name = "amdxdna_accel_driver",
	.desc = "AMD XDNA DRM implementation",
	.major = AMDXDNA_DRIVER_MAJOR,
	.minor = AMDXDNA_DRIVER_MINOR,
	.open = amdxdna_drm_open,
	.postclose = amdxdna_drm_close,
	.ioctls = amdxdna_drm_ioctls,
	.num_ioctls = ARRAY_SIZE(amdxdna_drm_ioctls),
	.show_fdinfo = amdxdna_show_fdinfo,
	.gem_create_object = amdxdna_gem_create_shmem_object_cb,
	.gem_prime_import = amdxdna_gem_prime_import,
};
