// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_accel.h>
#include <drm/drm_drv.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_managed.h>
#include <drm/gpu_scheduler.h>
#include <linux/iommu.h>
#include <linux/pci.h>

#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "amdxdna_drv.h"
#include "amdxdna_pm.h"

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
		XDNA_ERR(xdna, "SVA get pasid failed");
		return -ENODEV;
	}

	return 0;
}

static void amdxdna_sva_fini(struct amdxdna_client *client)
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
	struct amdxdna_client *client;

	client = kzalloc_obj(*client);
	if (!client)
		return -ENOMEM;

	client->pid = pid_nr(rcu_access_pointer(filp->pid));
	client->xdna = xdna;
	client->pasid = IOMMU_PASID_INVALID;
	client->mm = current->mm;

	if (!amdxdna_iova_on(xdna)) {
		/* No need to fail open since user may use pa + carveout later. */
		if (amdxdna_sva_init(client))
			XDNA_WARN(xdna, "PASID not available for pid %d", client->pid);
	}
	mmgrab(client->mm);
	init_srcu_struct(&client->hwctx_srcu);
	xa_init_flags(&client->hwctx_xa, XA_FLAGS_ALLOC);
	mutex_init(&client->mm_lock);
	INIT_LIST_HEAD(&client->dev_heap_chunks);

	mutex_lock(&xdna->dev_lock);
	list_add_tail(&client->node, &xdna->client_list);
	mutex_unlock(&xdna->dev_lock);

	filp->driver_priv = client;
	client->filp = filp;

	XDNA_DBG(xdna, "pid %d opened", client->pid);
	return 0;
}

static void amdxdna_client_cleanup(struct amdxdna_client *client)
{
	list_del(&client->node);
	amdxdna_hwctx_remove_all(client);
	xa_destroy(&client->hwctx_xa);
	cleanup_srcu_struct(&client->hwctx_srcu);

	while (!list_empty(&client->dev_heap_chunks)) {
		struct amdxdna_gem_obj *chunk;

		chunk = list_last_entry(&client->dev_heap_chunks,
					struct amdxdna_gem_obj, heap_chunk_node);
		list_del_init(&chunk->heap_chunk_node);
		drm_gem_object_put(to_gobj(chunk)); /* drop creation ref */
	}

	mutex_destroy(&client->mm_lock);
	mmdrop(client->mm);
	amdxdna_sva_fini(client);
	kfree(client);
}

static void amdxdna_drm_close(struct drm_device *ddev, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(ddev);
	int idx;

	XDNA_DBG(xdna, "closing pid %d", client->pid);

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return;

	mutex_lock(&xdna->dev_lock);
	amdxdna_client_cleanup(client);
	mutex_unlock(&xdna->dev_lock);

	drm_dev_exit(idx);
}

static void amdxdna_show_fdinfo(struct drm_printer *p, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	size_t heap_usage, external_usage, internal_usage;
	char *drv_name = filp->minor->dev->driver->name;

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

	guard(mutex)(&xdna->dev_lock);
	return xdna->dev_info->ops->get_array(client, args);
}

static int amdxdna_drm_set_state_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_set_state *args = data;
	int ret;

	if (!xdna->dev_info->ops->set_aie_state)
		return -EOPNOTSUPP;

	XDNA_DBG(xdna, "Request parameter %u", args->param);
	mutex_lock(&xdna->dev_lock);
	ret = xdna->dev_info->ops->set_aie_state(client, args);
	mutex_unlock(&xdna->dev_lock);

	return ret;
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

static const struct file_operations amdxdna_fops = {
	.owner		= THIS_MODULE,
	.open		= accel_open,
	.release	= drm_release,
	.unlocked_ioctl	= drm_ioctl,
	.compat_ioctl	= drm_compat_ioctl,
	.poll		= drm_poll,
	.read		= drm_read,
	.llseek		= noop_llseek,
	.mmap		= drm_gem_mmap,
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

/**
 * amdxdna_dev_init - amdxdna device init and registration
 * @xdna: Pointer to amdxdna device
 *
 * Initializes common device structures (mutex, rwsem, client list, workqueue),
 * hardware via ops->init, sysfs, and registers the DRM device in drm_dev_register() function.
 *
 * Return: 0 on success, negative error code on failure
 */
int amdxdna_dev_init(struct amdxdna_dev *xdna)
{
	int ret;

	drmm_mutex_init(&xdna->ddev, &xdna->dev_lock);
	INIT_LIST_HEAD(&xdna->client_list);

	mutex_lock(&xdna->dev_lock);
	ret = xdna->dev_info->ops->init(xdna);
	mutex_unlock(&xdna->dev_lock);
	if (ret) {
		XDNA_ERR(xdna, "Hardware init failed, ret %d", ret);
		return ret;
	}

	ret = amdxdna_sysfs_init(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Create amdxdna attrs failed: %d", ret);
		goto failed_dev_fini;
	}

	ret = drm_dev_register(&xdna->ddev, 0);
	if (ret) {
		XDNA_ERR(xdna, "DRM register failed, ret %d", ret);
		goto failed_sysfs_fini;
	}

	return 0;

failed_sysfs_fini:
	amdxdna_sysfs_fini(xdna);
failed_dev_fini:
	mutex_lock(&xdna->dev_lock);
	xdna->dev_info->ops->fini(xdna);
	mutex_unlock(&xdna->dev_lock);
	return ret;
}

/**
 * amdxdna_dev_cleanup - amdxdna device cleanup
 * @xdna: Pointer to amdxdna device
 *
 * Cleans up all clients and finalizes hardware.
 */
void amdxdna_dev_cleanup(struct amdxdna_dev *xdna)
{
	struct amdxdna_client *client;

	drm_dev_unplug(&xdna->ddev);
	amdxdna_sysfs_fini(xdna);

	mutex_lock(&xdna->dev_lock);
	client = list_first_entry_or_null(&xdna->client_list,
					  struct amdxdna_client, node);
	while (client) {
		amdxdna_client_cleanup(client);

		client = list_first_entry_or_null(&xdna->client_list,
						  struct amdxdna_client, node);
	}

	xdna->dev_info->ops->fini(xdna);
	mutex_unlock(&xdna->dev_lock);
}

