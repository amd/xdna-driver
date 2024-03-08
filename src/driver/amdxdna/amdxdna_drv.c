// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#include <linux/module.h>
#include <linux/iommu.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_accel.h>
#include <drm/drm_managed.h>
#include "drm_local/amdxdna_accel.h"

#include "amdxdna_drv.h"
#include "amdxdna_sysfs.h"
#include "npu_pci.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#define CREATE_TRACE_POINTS
#include "amdxdna_trace.h"

/*
 *  There are platforms which share the same PCI device ID
 *  but have different PCI revision IDs. So, let the PCI class
 *  determine the probe and later use the (device_id, rev_id)
 *  pair as a key to select the devices.
 */
static const struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_ANY_ID),
		.class = PCI_CLASS_SP_OTHER << 8,  /* Signal Processing */
		.class_mask = 0xFFFF00,
	},
	{0}
};

static const struct amdxdna_device_id amdxdna_ids[] = {
	{ 0x1502, 0, DEV_INFO_TO_DATA(NPU1) },
	{ 0x17f0, 0, DEV_INFO_TO_DATA(NPU2) },
	{ 0x17f0, 0x10, DEV_INFO_TO_DATA(NPU4) },
	{0}
};

MODULE_DEVICE_TABLE(pci, pci_ids);

static int amdxdna_drm_open(struct drm_device *ddev, struct drm_file *filp)
{
	struct amdxdna_dev *xdna = to_xdna_dev(ddev);
	struct amdxdna_client *client;
	int ret;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return -ENOMEM;

	client->pid = pid_nr(filp->pid);
	client->xdna = xdna;

#ifdef AMDXDNA_DEVEL
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_sva_bind;
#endif
	client->sva = iommu_sva_bind_device(&xdna->pdev->dev, current->mm);
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
	mutex_init(&client->hwctx_lock);
	init_srcu_struct(&client->hwctx_srcu);
	idr_init(&client->hwctx_idr);
	mutex_init(&client->mm_lock);
	client->dev_heap = AMDXDNA_INVALID_BO_HANDLE;

	mutex_lock(&xdna->dev_lock);
	list_add_tail(&client->node, &xdna->client_list);
	mutex_unlock(&xdna->dev_lock);

	filp->driver_priv = client;

	XDNA_DBG(xdna, "pid %d opened", client->pid);
	return 0;

unbind_sva:
	iommu_sva_unbind_device(client->sva);
failed:
	kfree(client);

	return ret;
}

static void amdxdna_drm_close(struct drm_device *ddev, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(ddev);

	XDNA_DBG(xdna, "closing pid %d", client->pid);

	mutex_lock(&xdna->dev_lock);
	list_del(&client->node);
	amdxdna_hwctx_remove_all(client);
	mutex_unlock(&xdna->dev_lock);

	idr_destroy(&client->hwctx_idr);
	cleanup_srcu_struct(&client->hwctx_srcu);
	mutex_destroy(&client->hwctx_lock);
	mutex_destroy(&client->mm_lock);

#ifdef AMDXDNA_DEVEL
	if (iommu_mode != AMDXDNA_IOMMU_PASID)
		goto skip_sva_unbind;
#endif
	iommu_sva_unbind_device(client->sva);
#ifdef AMDXDNA_DEVEL
skip_sva_unbind:
#endif

	XDNA_DBG(xdna, "pid %d closed", client->pid);
	kfree(client);
}

static int get_info_aie_metadata(struct amdxdna_dev *xdna, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_aie_metadata *aie_struct;
	int ret = 0;
	int idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	aie_struct = kzalloc(sizeof(*aie_struct), GFP_KERNEL);
	if (!aie_struct) {
		ret = -ENOMEM;
		goto fail;
	}

	npu_get_aie_metadata(xdna, aie_struct);

	if (copy_to_user(u64_to_user_ptr(args->buffer), aie_struct, sizeof(*aie_struct))) {
		ret = -EFAULT;
		XDNA_ERR(xdna, "Failed to copy AIE request into user space");
		goto fail_copy;
	}

fail_copy:
	kfree(aie_struct);
fail:
	drm_dev_exit(idx);
	return ret;
}

static int get_info_aie_status(struct amdxdna_dev *xdna, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_aie_status *aie_struct;
	u32 input_buf_size;
	int ret, idx;

	input_buf_size = args->buffer_size;
	args->buffer_size = sizeof(*aie_struct);
	if (input_buf_size != sizeof(*aie_struct)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %lu.",
			 input_buf_size, sizeof(*aie_struct));
		ret = -EINVAL;
		goto fail;
	}

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	aie_struct = kzalloc(sizeof(*aie_struct), GFP_KERNEL);
	if (!aie_struct) {
		ret = -ENOMEM;
		goto fail;
	}

	if (copy_from_user(aie_struct, u64_to_user_ptr(args->buffer), sizeof(*aie_struct))) {
		ret = -EFAULT;
		XDNA_ERR(xdna, "Failed to copy AIE request into kernel");
		goto fail_copy;
	}

	ret = npu_get_aie_status(xdna, aie_struct);

	if (copy_to_user(u64_to_user_ptr(args->buffer), aie_struct, sizeof(*aie_struct))) {
		ret = -EFAULT;
		XDNA_ERR(xdna, "Failed to copy AIE request into user space");
		goto fail_copy;
	}

fail_copy:
	kfree(aie_struct);
fail:
	drm_dev_exit(idx);
	return ret;
}

static int get_info_aie_version(struct amdxdna_dev *xdna, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_aie_version *aie_struct;
	int ret = 0;
	int idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	aie_struct = kzalloc(sizeof(*aie_struct), GFP_KERNEL);
	if (!aie_struct) {
		ret = -ENOMEM;
		goto fail;
	}

	npu_get_aie_version(xdna, aie_struct);

	if (copy_to_user(u64_to_user_ptr(args->buffer), aie_struct, sizeof(*aie_struct))) {
		ret = -EFAULT;
		XDNA_ERR(xdna, "Failed to copy AIE request into user space");
		goto fail_copy;
	}

fail_copy:
	kfree(aie_struct);
fail:
	drm_dev_exit(idx);
	return ret;
}

static int get_info_clock_metadata(struct amdxdna_dev *xdna, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_clock_metadata *clock_struct;
	u32 input_buf_size;
	int ret = 0;
	int idx;

	input_buf_size = args->buffer_size;
	args->buffer_size = sizeof(*clock_struct);
	if (input_buf_size != sizeof(*clock_struct)) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %lu.",
			 input_buf_size, sizeof(*clock_struct));
		ret = -EINVAL;
		goto exit;
	}

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	clock_struct = kzalloc(sizeof(*clock_struct), GFP_KERNEL);
	if (!clock_struct) {
		ret = -ENOMEM;
		goto exit;
	}

	npu_get_clock_metadata(xdna, clock_struct);

	if (copy_to_user(u64_to_user_ptr(args->buffer), clock_struct, sizeof(*clock_struct))) {
		ret = -EFAULT;
		XDNA_ERR(xdna, "Failed to copy clock request into user space");
		goto release;
	}

release:
	kfree(clock_struct);
exit:
	drm_dev_exit(idx);
	return ret;
}

static int get_info_sensors(struct amdxdna_dev *xdna, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_sensor *sensor;
	u32 input_buf_size;
	int ret = 0;
	int idx;

	input_buf_size = args->buffer_size;
	args->buffer_size = sizeof(*sensor);
	if (input_buf_size < args->buffer_size) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %lu.",
			 input_buf_size, sizeof(*sensor));
		ret = -EINVAL;
		goto out;
	}

	if (!drm_dev_enter(&xdna->ddev, &idx)) {
		ret = -ENODEV;
		goto out;
	}

	sensor = kzalloc(sizeof(*sensor), GFP_KERNEL);
	if (!sensor) {
		ret = -ENOMEM;
		goto out_mem;
	}

	ret = npu_query_power_sensor(xdna->dev_handle, sensor);
	if (ret) {
		ret = -EFAULT;
		XDNA_ERR(xdna, "Failed to query power sensor data");
		goto out_copy;
	}

	if (copy_to_user(u64_to_user_ptr(args->buffer), sensor, sizeof(*sensor))) {
		ret = -EFAULT;
		XDNA_ERR(xdna, "Failed to copy sensor data into user space");
		goto out_copy;
	}

out_copy:
	kfree(sensor);
out_mem:
	drm_dev_exit(idx);
out:
	return ret;
}

static int amdxdna_drm_get_info_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_drm_get_info *args = data;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	int ret = -EINVAL;

	XDNA_DBG(xdna, "Request parameter %u", args->param);
	switch (args->param) {
	case DRM_AMDXDNA_QUERY_AIE_STATUS:
		ret = get_info_aie_status(xdna, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_METADATA:
		ret = get_info_aie_metadata(xdna, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_VERSION:
		ret = get_info_aie_version(xdna, args);
		break;
	case DRM_AMDXDNA_QUERY_CLOCK_METADATA:
		ret = get_info_clock_metadata(xdna, args);
		break;
	case DRM_AMDXDNA_QUERY_SENSORS:
		ret = get_info_sensors(xdna, args);
		break;
	case DRM_AMDXDNA_QUERY_HW_CONTEXTS:
		ret = amdxdna_hwctx_status(dev, &args->buffer_size, u64_to_user_ptr(args->buffer));
		break;
	default:
		XDNA_ERR(xdna, "Bad request parameter %u", args->param);
		break;
	}

	return ret;
}

static const struct drm_ioctl_desc amdxdna_drm_ioctls[] = {
	/* Context */
	DRM_IOCTL_DEF_DRV(AMDXDNA_CREATE_HWCTX, amdxdna_drm_create_hwctx_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_DESTROY_HWCTX, amdxdna_drm_destroy_hwctx_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_CREATE_HWCTX_LEGACY, amdxdna_drm_create_hwctx_legacy_ioctl, 0),
#ifdef AMDXDNA_DEVEL
	DRM_IOCTL_DEF_DRV(AMDXDNA_CREATE_HWCTX_UNSECURE, amdxdna_drm_create_hwctx_unsec_ioctl, 0),
#endif
	/* BO */
	DRM_IOCTL_DEF_DRV(AMDXDNA_CREATE_BO, amdxdna_drm_create_bo_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_GET_BO_INFO, amdxdna_drm_get_bo_info_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_SYNC_BO, amdxdna_drm_sync_bo_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_ATTACH_BO, amdxdna_drm_attach_bo_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_DETACH_BO, amdxdna_drm_detach_bo_ioctl, 0),
	/* Exectuion */
	DRM_IOCTL_DEF_DRV(AMDXDNA_EXEC_CMD, amdxdna_drm_exec_cmd_ioctl, 0),
	DRM_IOCTL_DEF_DRV(AMDXDNA_WAIT_CMD, amdxdna_drm_wait_cmd_ioctl, 0),
	/* Query */
	DRM_IOCTL_DEF_DRV(AMDXDNA_GET_INFO, amdxdna_drm_get_info_ioctl, 0),
};

DEFINE_DRM_ACCEL_FOPS(amdxdna_fops);

static const struct drm_driver amdxdna_drm_drv = {
	.driver_features = DRIVER_GEM | DRIVER_COMPUTE_ACCEL,
	.fops = &amdxdna_fops,
	.name = "amdxdna_accel_driver",
	.desc = "AMD XDNA DRM implementation",
	.date = "20240124",
	.major = AMDXDNA_DRIVER_MAJOR,
	.minor = AMDXDNA_DRIVER_MINOR,
	.open = amdxdna_drm_open,
	.postclose = amdxdna_drm_close,
	.ioctls = amdxdna_drm_ioctls,
	.num_ioctls = ARRAY_SIZE(amdxdna_drm_ioctls),

	/* For shmem object create */
	.gem_create_object = amdxdna_gem_create_object,
};

static struct amdxdna_dev_info *amdxdna_get_dev_info(struct pci_dev *pdev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(amdxdna_ids); i++) {
		if (pdev->device == amdxdna_ids[i].device &&
		    pdev->revision == amdxdna_ids[i].revision)
			return amdxdna_ids[i].dev_info;
	}
	return NULL;
}

static int amdxdna_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct amdxdna_dev *xdna;
	int ret;

	xdna = devm_drm_dev_alloc(&pdev->dev, &amdxdna_drm_drv, typeof(*xdna), ddev);
	if (IS_ERR(xdna))
		return PTR_ERR(xdna);

	xdna->pdev = pdev;
	xdna->dev_info = amdxdna_get_dev_info(pdev);
	if (!xdna->dev_info)
		return -ENODEV;

	drmm_mutex_init(&xdna->ddev, &xdna->dev_lock);
	INIT_LIST_HEAD(&xdna->client_list);
	INIT_LIST_HEAD(&xdna->xclbin_list);
	pci_set_drvdata(pdev, xdna);

	ret = npu_init(xdna);
	if (ret) {
		XDNA_ERR(xdna, "hardware init failed, ret %d", ret);
		goto failed;
	}

	ret = amdxdna_sysfs_init(xdna);
	if (ret) {
		XDNA_ERR(xdna, "create amdxdna attrs failed: %d", ret);
		goto failed_npu_fini;
	}

	ret = drm_dev_register(&xdna->ddev, 0);
	if (ret) {
		XDNA_ERR(xdna, "DRM register failed, ret %d", ret);
		goto failed_sysfs_fini;
	}

	npu_debugfs_add(xdna->dev_handle);
	ida_init(&xdna->pdi_ida);

	return 0;

failed_sysfs_fini:
	amdxdna_sysfs_fini(xdna);
failed_npu_fini:
	npu_fini(xdna);
failed:
	return ret;
}

static void amdxdna_remove(struct pci_dev *pdev)
{
	struct amdxdna_dev *xdna = pci_get_drvdata(pdev);
	struct amdxdna_client *client, *tmp;

	drm_dev_unplug(&xdna->ddev);
	amdxdna_sysfs_fini(xdna);

	mutex_lock(&xdna->dev_lock);
	list_for_each_entry_safe(client, tmp, &xdna->client_list, node)
		amdxdna_hwctx_remove_all(client);
	mutex_unlock(&xdna->dev_lock);

	npu_fini(xdna);
	ida_destroy(&xdna->pdi_ida);
}

static int amdxdna_pmops_suspend(struct device *dev)
{
	struct amdxdna_dev *xdna = pci_get_drvdata(to_pci_dev(dev));
	struct amdxdna_client *client;

	mutex_lock(&xdna->dev_lock);
	list_for_each_entry(client, &xdna->client_list, node)
		amdxdna_hwctx_suspend(client);
	mutex_unlock(&xdna->dev_lock);

	npu_hw_stop(xdna->dev_handle);

	return 0;
}

static int amdxdna_pmops_resume(struct device *dev)
{
	struct amdxdna_dev *xdna = pci_get_drvdata(to_pci_dev(dev));
	struct amdxdna_client *client;
	int ret;

	XDNA_INFO(xdna, "firmware resuming...");
	ret = npu_hw_start(xdna->dev_handle);
	if (ret) {
		XDNA_ERR(xdna, "resume NPU firmware failed");
		return ret;
	}

	XDNA_INFO(xdna, "hardware context resuming...");
	mutex_lock(&xdna->dev_lock);
	list_for_each_entry(client, &xdna->client_list, node)
		amdxdna_hwctx_resume(client);
	mutex_unlock(&xdna->dev_lock);

	return 0;
}

static const struct dev_pm_ops amdxdna_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(amdxdna_pmops_suspend, amdxdna_pmops_resume)
};

static struct pci_driver amdxdna_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = pci_ids,
	.probe = amdxdna_probe,
	.remove = amdxdna_remove,
	.driver.pm = &amdxdna_pm_ops,
};

module_pci_driver(amdxdna_pci_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XRT Team <runtimeca39d@amd.com>");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("amdxdna driver");
