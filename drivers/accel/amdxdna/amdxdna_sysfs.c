// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_device.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_print.h>
#include <drm/gpu_scheduler.h>
#include <linux/dma-map-ops.h>
#include <linux/types.h>

#include "amdxdna_gem.h"
#include "amdxdna_drv.h"

static ssize_t vbnv_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct amdxdna_dev *xdna = dev_get_drvdata(dev);

	if (!xdna->vbnv)
		return sprintf(buf, "\n");

	return sprintf(buf, "%s\n", xdna->vbnv);
}
static DEVICE_ATTR_RO(vbnv);

static ssize_t device_type_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct amdxdna_dev *xdna = dev_get_drvdata(dev);
	int type = xdna->dev_info->device_type;

	/*
	 * A UMQ part is DMA-coherent on x86 (PCIe) but not on the aarch64
	 * platform; report the non-coherent variant so userspace can pick its
	 * cache-maintenance policy from the device type alone.
	 */
	if (type == AMDXDNA_DEV_TYPE_UMQ && !dev_is_dma_coherent(xdna->ddev.dev))
		type = AMDXDNA_DEV_TYPE_UMQ_NONCOHERENT;

	return sprintf(buf, "%d\n", type);
}
static DEVICE_ATTR_RO(device_type);

static ssize_t fw_version_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct amdxdna_dev *xdna = dev_get_drvdata(dev);

	return sprintf(buf, "%d.%d.%d.%d\n", xdna->fw_ver.major,
		       xdna->fw_ver.minor, xdna->fw_ver.patch,
		       xdna->fw_ver.build);
}
static DEVICE_ATTR_RO(fw_version);

static struct attribute *amdxdna_attrs[] = {
	&dev_attr_device_type.attr,
	&dev_attr_vbnv.attr,
	&dev_attr_fw_version.attr,
	NULL,
};

static struct attribute_group amdxdna_attr_group = {
	.attrs = amdxdna_attrs,
};

int amdxdna_sysfs_init(struct amdxdna_dev *xdna)
{
	int ret;

	ret = sysfs_create_group(&xdna->ddev.dev->kobj, &amdxdna_attr_group);
	if (ret)
		XDNA_ERR(xdna, "Create attr group failed");

	return ret;
}

void amdxdna_sysfs_fini(struct amdxdna_dev *xdna)
{
	sysfs_remove_group(&xdna->ddev.dev->kobj, &amdxdna_attr_group);
}
