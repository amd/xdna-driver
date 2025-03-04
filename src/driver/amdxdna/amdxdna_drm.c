// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2025, Advanced Micro Devices, Inc.
 */

#include <linux/iommu.h>
#include <linux/pm_runtime.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_accel.h>
#include "drm_local/amdxdna_accel.h"

#include "amdxdna_drm.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#define CREATE_TRACE_POINTS
#include "amdxdna_trace.h"

static int amdxdna_drm_open(struct drm_device *ddev, struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(ddev);
	struct amdxdna_client *client;
	int ret;

	ret = pm_runtime_resume_and_get(ddev->dev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to get rpm, ret %d", ret);
		return ret;
	}

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client) {
		ret = -ENOMEM;
		goto put_rpm;
	}

	client->pid = pid_nr(filp->pid);
	client->xdna = xdna;

#ifdef AMDXDNA_DEVEL
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_sva_bind;
#endif
	client->sva = iommu_sva_bind_device(xdna->ddev.dev, current->mm);
	if (IS_ERR(client->sva)) {
		ret = PTR_ERR(client->sva);
		XDNA_ERR(xdna, "SVA bind device failed, ret %d", ret);
		goto failed;
	}
	client->pasid = iommu_sva_get_pasid(client->sva);
	if (client->pasid == IOMMU_PASID_INVALID) {
		XDNA_ERR(xdna, "SVA get pasid failed");
		ret = -ENODEV;
		goto unbind_sva;
	}
#ifdef AMDXDNA_DEVEL
skip_sva_bind:
#endif
	init_srcu_struct(&client->ctx_srcu);
	xa_init_flags(&client->ctx_xa, XA_FLAGS_ALLOC);
	mutex_init(&client->mm_lock);

	mutex_lock(&xdna->dev_lock);
	list_add_tail(&client->node, &xdna->client_list);
	mutex_unlock(&xdna->dev_lock);

	spin_lock_init(&client->stats.lock);
	client->stats.job_depth = 0;
	client->stats.busy_time = ns_to_ktime(0);
	client->stats.start_time = ns_to_ktime(0);

	filp->driver_priv = client;
	client->filp = filp;

	XDNA_DBG(xdna, "PID %d opened", client->pid);
	return 0;

unbind_sva:
	iommu_sva_unbind_device(client->sva);
failed:
	kfree(client);
put_rpm:
	pm_runtime_mark_last_busy(ddev->dev);
	pm_runtime_put_autosuspend(ddev->dev);

	return ret;
}

static void amdxdna_drm_close(struct drm_device *ddev, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(ddev);

	XDNA_DBG(xdna, "Closing PID %d", client->pid);

	xa_destroy(&client->ctx_xa);
	cleanup_srcu_struct(&client->ctx_srcu);
	mutex_destroy(&client->mm_lock);
	if (client->dev_heap)
		drm_gem_object_put(to_gobj(client->dev_heap));

#ifdef AMDXDNA_DEVEL
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_sva_unbind;
#endif
	iommu_sva_unbind_device(client->sva);
#ifdef AMDXDNA_DEVEL
skip_sva_unbind:
#endif

	XDNA_DBG(xdna, "PID %d closed", client->pid);
	kfree(client);
	pm_runtime_mark_last_busy(ddev->dev);
	pm_runtime_put_autosuspend(ddev->dev);
}

static int amdxdna_flush(struct file *f, fl_owner_t id)
{
	struct drm_file *filp = f->private_data;
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = client->xdna;
	pid_t pid = task_tgid_nr(current);
	int idx;

	/* When current PID not equals to Client PID, this is a flush()
	 * triggered by closing a child process. If this is the case, flush() is
	 * just a no-op. The process which open() device should finally flush()
	 * and close() device.
	 */
	if (pid != client->pid)
		return 0;

	XDNA_DBG(xdna, "PID %d flushing...", client->pid);
	if (!drm_dev_enter(&xdna->ddev, &idx))
		return 0;

	mutex_lock(&xdna->dev_lock);
	list_del_init(&client->node);
	mutex_unlock(&xdna->dev_lock);
	amdxdna_ctx_remove_all(client);

	drm_dev_exit(idx);
	return 0;
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

	return xdna->dev_info->ops->mmap(xdna, vma);
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
	ret = xdna->dev_info->ops->get_aie_info(client, args);
	return ret;
}

static int amdxdna_drm_set_state_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_set_state *args = data;
	int ret = 0;

	if (!xdna->dev_info->ops->set_aie_state)
		return -EOPNOTSUPP;

	XDNA_DBG(xdna, "Request parameter %u", args->param);
	ret = xdna->dev_info->ops->set_aie_state(client, args);
	return ret;
}

static const struct drm_ioctl_desc amdxdna_drm_ioctls[] = {
	/* Context */
	DRM_IOCTL_DEF_DRV(AMDXDNA_CREATE_CTX, amdxdna_drm_create_ctx_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_DESTROY_CTX, amdxdna_drm_destroy_ctx_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_CONFIG_CTX, amdxdna_drm_config_ctx_ioctl, 0),
	/* BO */
	DRM_IOCTL_DEF_DRV(AMDXDNA_CREATE_BO, amdxdna_drm_create_bo_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_GET_BO_INFO, amdxdna_drm_get_bo_info_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_SYNC_BO, amdxdna_drm_sync_bo_ioctl, 0),
	/* Exectuion */
	DRM_IOCTL_DEF_DRV(AMDXDNA_EXEC_CMD, amdxdna_drm_submit_cmd_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_WAIT_CMD, amdxdna_drm_wait_cmd_ioctl, 0),
	/* AIE hardware */
	DRM_IOCTL_DEF_DRV(AMDXDNA_GET_INFO, amdxdna_drm_get_info_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_SET_STATE, amdxdna_drm_set_state_ioctl, DRM_ROOT_ONLY),
};

void amdxdna_update_stats(struct amdxdna_client *client, ktime_t time, bool start)
{
	unsigned long flags;

	spin_lock_irqsave(&client->stats.lock, flags);
	if (start) {
		client->stats.job_depth++;
		if (client->stats.job_depth == 1)
			client->stats.start_time = time;
	} else {
		client->stats.job_depth--;
		if (client->stats.job_depth == 0)
			client->stats.busy_time =
				ktime_add(client->stats.busy_time,
					  ktime_sub(time, client->stats.start_time));
	}
	spin_unlock_irqrestore(&client->stats.lock, flags);
}

static void amdxdna_show_fdinfo(struct drm_printer *p, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	const char *engine_npu_name = "npu-amdxdna";
	unsigned long flags;
	u64 busy_ns;

	spin_lock_irqsave(&client->stats.lock, flags);
	busy_ns = ktime_to_ns(client->stats.busy_time);
	if (client->stats.job_depth > 0)
		busy_ns += ktime_to_ns(ktime_sub(ktime_get(), client->stats.start_time));
	spin_unlock_irqrestore(&client->stats.lock, flags);

	/* see Documentation/gpu/drm-usage-stats.rst */
	drm_printf(p, "drm-engine-%s:\t%llu ns\n", engine_npu_name, busy_ns);

	drm_show_memory_stats(p, filp);
}

static const struct file_operations amdxdna_fops = {
	.owner		= THIS_MODULE,
	.open		= accel_open,
	.release	= drm_release,
	.flush		= amdxdna_flush,
	.unlocked_ioctl	= drm_ioctl,
	.compat_ioctl	= drm_compat_ioctl,
	.poll		= drm_poll,
	.read		= drm_read,
	.llseek		= noop_llseek,
	.mmap		= amdxdna_drm_gem_mmap,
	.show_fdinfo	= drm_show_fdinfo,
#ifdef FOP_UNSIGNED_OFFSET
	.fop_flags      = FOP_UNSIGNED_OFFSET,
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

	/* For shmem object create */
	.gem_create_object = amdxdna_gem_create_shmem_object_cb,
#ifdef AMDXDNA_SHMEM
	.gem_prime_import = amdxdna_gem_prime_import,
#else
	.gem_prime_import_sg_table = drm_gem_dma_prime_import_sg_table,
#endif
};
