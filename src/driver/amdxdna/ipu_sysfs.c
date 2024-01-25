// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 *
 * Authors:
 *	Daniel Benusovich <daniel.benusovich@amd.com>
 */
#include <linux/stringify.h>
#include "ipu_common.h"

#include "sysfs_mgr.h"

static ssize_t
type_show(struct device *dev, struct sysfs_mgr_node *node,
	  struct sysfs_mgr_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", 3); /* System clock type */
}
static SYSFS_MGR_ATTR_RO(type);

static ssize_t
freq_show(struct device *dev, struct sysfs_mgr_node *node,
	  struct sysfs_mgr_attribute *attr, char *buf)
{
	struct clock_entry *clock = container_of(node, struct clock_entry, node);

	return sprintf(buf, "%u\n", clock->freq_mhz);
}
static SYSFS_MGR_ATTR_RO(freq);

static ssize_t
name_show(struct device *dev, struct sysfs_mgr_node *node,
	  struct sysfs_mgr_attribute *attr, char *buf)
{
	struct clock_entry *clock = container_of(node, struct clock_entry, node);

	return sprintf(buf, "%s\n", clock->name);
}
static SYSFS_MGR_ATTR_RO(name);

static struct attribute *clock_entry_attrs[] = {
	&sysfs_mgr_attr_freq.attr,
	&sysfs_mgr_attr_name.attr,
	&sysfs_mgr_attr_type.attr,
	NULL,
};

static struct attribute_group clock_entry_group = {
	.attrs = clock_entry_attrs,
};

static ssize_t
major_show(struct device *dev, struct sysfs_mgr_node *node,
	   struct sysfs_mgr_attribute *attr, char *buf)
{
	struct aie_version *version = container_of(node, struct aie_version, node);

	return sprintf(buf, "%u\n", version->major);
}
static SYSFS_MGR_ATTR_RO(major);

static ssize_t
minor_show(struct device *dev, struct sysfs_mgr_node *node,
	   struct sysfs_mgr_attribute *attr, char *buf)
{
	struct aie_version *version = container_of(node, struct aie_version, node);

	return sprintf(buf, "%u\n", version->minor);
}
static SYSFS_MGR_ATTR_RO(minor);

static struct attribute *version_attrs[] = {
	&sysfs_mgr_attr_major.attr,
	&sysfs_mgr_attr_minor.attr,
	NULL,
};

static struct attribute_group version_group = {
	.attrs = version_attrs,
};

static ssize_t
size_show(struct device *dev, struct sysfs_mgr_node *node,
	  struct sysfs_mgr_attribute *attr, char *buf)
{
	struct aie_metadata *metadata = container_of(node, struct aie_metadata, node);

	return sprintf(buf, "%u\n", metadata->size);
}
static SYSFS_MGR_ATTR_RO(size);

static ssize_t
cols_show(struct device *dev, struct sysfs_mgr_node *node,
	  struct sysfs_mgr_attribute *attr, char *buf)
{
	struct aie_metadata *metadata = container_of(node, struct aie_metadata, node);

	return sprintf(buf, "%u\n", metadata->cols);
}
static SYSFS_MGR_ATTR_RO(cols);

static ssize_t
rows_show(struct device *dev, struct sysfs_mgr_node *node,
	  struct sysfs_mgr_attribute *attr, char *buf)
{
	struct aie_metadata *metadata = container_of(node, struct aie_metadata, node);

	return sprintf(buf, "%u\n", metadata->rows);
}
static SYSFS_MGR_ATTR_RO(rows);

static struct attribute *metadata_attrs[] = {
	&sysfs_mgr_attr_size.attr,
	&sysfs_mgr_attr_cols.attr,
	&sysfs_mgr_attr_rows.attr,
	NULL,
};

static struct attribute_group metadata_group = {
	.attrs = metadata_attrs,
};

static ssize_t
row_count_show(struct device *dev, struct sysfs_mgr_node *node,
	       struct sysfs_mgr_attribute *attr, char *buf)
{
	struct aie_tile_metadata *metadata = container_of(node, struct aie_tile_metadata, node);

	return sprintf(buf, "%u\n", metadata->row_count);
}
static SYSFS_MGR_ATTR_RO(row_count);

static ssize_t
row_start_show(struct device *dev, struct sysfs_mgr_node *node,
	       struct sysfs_mgr_attribute *attr, char *buf)
{
	struct aie_tile_metadata *metadata = container_of(node, struct aie_tile_metadata, node);

	return sprintf(buf, "%u\n", metadata->row_start);
}
static SYSFS_MGR_ATTR_RO(row_start);

static ssize_t
dma_channel_count_show(struct device *dev, struct sysfs_mgr_node *node,
		       struct sysfs_mgr_attribute *attr, char *buf)
{
	struct aie_tile_metadata *metadata = container_of(node, struct aie_tile_metadata, node);

	return sprintf(buf, "%u\n", metadata->dma_channel_count);
}
static SYSFS_MGR_ATTR_RO(dma_channel_count);

static ssize_t
lock_count_show(struct device *dev, struct sysfs_mgr_node *node,
		struct sysfs_mgr_attribute *attr, char *buf)
{
	struct aie_tile_metadata *metadata = container_of(node, struct aie_tile_metadata, node);

	return sprintf(buf, "%u\n", metadata->lock_count);
}
static SYSFS_MGR_ATTR_RO(lock_count);

static ssize_t
event_reg_count_show(struct device *dev, struct sysfs_mgr_node *node,
		     struct sysfs_mgr_attribute *attr, char *buf)
{
	struct aie_tile_metadata *metadata = container_of(node, struct aie_tile_metadata, node);

	return sprintf(buf, "%u\n", metadata->event_reg_count);
}
static SYSFS_MGR_ATTR_RO(event_reg_count);

static struct attribute *tile_metadata_attrs[] = {
	&sysfs_mgr_attr_row_count.attr,
	&sysfs_mgr_attr_row_start.attr,
	&sysfs_mgr_attr_dma_channel_count.attr,
	&sysfs_mgr_attr_lock_count.attr,
	&sysfs_mgr_attr_event_reg_count.attr,
	NULL,
};

static struct attribute_group tile_metadata_group = {
	.attrs = tile_metadata_attrs,
};

#define GEN_DIR_AND_ATTRS(idev, parent, attrs, data, name, err, fail) \
	err = sysfs_mgr_generate_directory(idev->xdna->sysfs_mgr, parent, attrs, data, name); \
	if (err) { \
		XDNA_ERR(idev->xdna, "Failed to generate %s directory", \
			 __stringify(parent)" "name); \
		goto fail; \
	}

int ipu_sysfs_init(struct ipu_device *idev)
{
	int ret;

	ret = sysfs_mgr_generate_directory(idev->xdna->sysfs_mgr, NULL, NULL,
					   &idev->clocks_dir, "clocks");
	if (ret) {
		XDNA_ERR(idev->xdna, "Failed to initialize clocks directory. ret: %d", ret);
		return ret;
	}

	ret = sysfs_mgr_generate_directory(idev->xdna->sysfs_mgr, NULL, NULL,
					   &idev->aie_dir, "xdna");
	if (ret) {
		XDNA_ERR(idev->xdna, "Failed to initialize xdna directory. ret: %d", ret);
		goto rm_clock_dir;
	}

	GEN_DIR_AND_ATTRS(idev, &idev->clocks_dir, &clock_entry_group,
			  &idev->mp_ipu_clock.node, "0", ret, rm_aie_dir);

	GEN_DIR_AND_ATTRS(idev, &idev->clocks_dir, &clock_entry_group,
			  &idev->h_clock.node, "1", ret, rm_aie_dir);

	GEN_DIR_AND_ATTRS(idev, &idev->aie_dir, &version_group,
			  &idev->version.node, "version", ret, rm_aie_dir);

	GEN_DIR_AND_ATTRS(idev, &idev->aie_dir, &metadata_group,
			  &idev->metadata.node, "metadata", ret, rm_aie_dir);

	GEN_DIR_AND_ATTRS(idev, &idev->metadata.node, &version_group,
			  &idev->metadata.version.node, "version", ret, rm_aie_dir);

	GEN_DIR_AND_ATTRS(idev, &idev->metadata.node, &tile_metadata_group,
			  &idev->metadata.core.node, "core", ret, rm_aie_dir);

	GEN_DIR_AND_ATTRS(idev, &idev->metadata.node, &tile_metadata_group,
			  &idev->metadata.mem.node, "mem", ret, rm_aie_dir);

	GEN_DIR_AND_ATTRS(idev, &idev->metadata.node, &tile_metadata_group,
			  &idev->metadata.shim.node, "shim", ret, rm_aie_dir);

	return 0;

rm_aie_dir:
	sysfs_mgr_remove_directory(idev->xdna->sysfs_mgr, &idev->aie_dir);
rm_clock_dir:
	sysfs_mgr_remove_directory(idev->xdna->sysfs_mgr, &idev->clocks_dir);
	return ret;
}

void ipu_sysfs_fini(struct ipu_device *idev)
{
	sysfs_mgr_remove_directory(idev->xdna->sysfs_mgr, &idev->clocks_dir);
	sysfs_mgr_remove_directory(idev->xdna->sysfs_mgr, &idev->aie_dir);
}
