// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */
#include "amdxdna_sysfs.h"
#include "amdxdna_ctx.h"
#include "ipu_pci.h"

static ssize_t vbnv_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct amdxdna_dev *xdna = dev_get_drvdata(dev);

	return sprintf(buf, "%s\n", xdna->dev_info->vbnv);
}
static DEVICE_ATTR_RO(vbnv);

static ssize_t device_type_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct amdxdna_dev *xdna = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", xdna->dev_info->device_type);
}
static DEVICE_ATTR_RO(device_type);

static struct attribute *amdxdna_attrs[] = {
	&dev_attr_device_type.attr,
	&dev_attr_vbnv.attr,
	NULL,
};

static struct attribute_group amdxdna_attr_group = {
	.attrs = amdxdna_attrs,
};

static ssize_t
start_col_show(struct device *dev, struct sysfs_mgr_node *node,
	       struct sysfs_mgr_attribute *attr, char *buf)
{
	struct amdxdna_hwctx *hwctx = container_of(node, struct amdxdna_hwctx, dir);

	return sprintf(buf, "%u\n", hwctx->start_col);
}
static SYSFS_MGR_ATTR_RO(start_col);

static ssize_t
num_col_show(struct device *dev, struct sysfs_mgr_node *node,
	     struct sysfs_mgr_attribute *attr, char *buf)
{
	struct amdxdna_hwctx *hwctx = container_of(node, struct amdxdna_hwctx, dir);

	return sprintf(buf, "%u\n", hwctx->num_col);
}
static SYSFS_MGR_ATTR_RO(num_col);

static ssize_t
next_seq_number_show(struct device *dev, struct sysfs_mgr_node *node,
		     struct sysfs_mgr_attribute *attr, char *buf)
{
	struct amdxdna_hwctx *hwctx = container_of(node, struct amdxdna_hwctx, dir);

	return sprintf(buf, "%llu\n", hwctx->seq);
}
static SYSFS_MGR_ATTR_RO(next_seq_number);

static struct attribute *hwctx_attrs[] = {
	&sysfs_mgr_attr_start_col.attr,
	&sysfs_mgr_attr_num_col.attr,
	&sysfs_mgr_attr_next_seq_number.attr,
	NULL,
};

struct attribute_group hwctx_group = {
	.attrs = hwctx_attrs,
};

int amdxdna_sysfs_init(struct amdxdna_dev *xdna)
{
	int ret;

	ret = sysfs_create_group(&xdna->pdev->dev.kobj, &amdxdna_attr_group);
	if (ret) {
		XDNA_ERR(xdna, "Create attr group failed");
		return ret;
	}

	xdna->sysfs_mgr = sysfs_mgr_init(&xdna->pdev->dev);
	if (IS_ERR(xdna->sysfs_mgr)) {
		ret = PTR_ERR(xdna->sysfs_mgr);
		XDNA_ERR(xdna, "Sysfs manager init failed, ret %d", ret);
		goto remove_group;
	}

	ret = sysfs_mgr_generate_directory(xdna->sysfs_mgr, NULL, NULL,
					   &xdna->clients_dir, "clients");
	if (ret) {
		XDNA_ERR(xdna, "Create clients directory failed, %d", ret);
		goto mgr_fini;
	}

	ret = ipu_sysfs_init(xdna->dev_handle);
	if (ret) {
		XDNA_ERR(xdna, "IPU sysfs init failed, %d", ret);
		goto mgr_fini;
	}

	return 0;

mgr_fini:
	sysfs_mgr_cleanup(xdna->sysfs_mgr);
	xdna->sysfs_mgr = NULL;
remove_group:
	sysfs_remove_group(&xdna->pdev->dev.kobj, &amdxdna_attr_group);
	return ret;
}

void amdxdna_sysfs_fini(struct amdxdna_dev *xdna)
{
	ipu_sysfs_fini(xdna->dev_handle);
	sysfs_mgr_cleanup(xdna->sysfs_mgr);
	sysfs_remove_group(&xdna->pdev->dev.kobj, &amdxdna_attr_group);
}
