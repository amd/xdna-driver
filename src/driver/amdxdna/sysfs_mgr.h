/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023, Advanced Micro Devices, Inc.  All rights reserved.
 *
 * Authors:
 *	Daniel Benusovich <daniel.benusovich@amd.com>
 */
#ifndef SYSFS_MGR_H
#define SYSFS_MGR_H

#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

/*
 * struct sysfs_mgr_node - The container tha manages a sysfs directory
 *
 * By embedding this node into a structure, it can represent a sysfs
 * directory when added into the sysfs manager. The attribute callbacks
 * registered to this node will allow access to the original structure
 * via containerof calls. Additional nodes can be linked to this node
 * to form a complex directory layout.
 *
 * @mgr: A reference to the sysfs manager that controls this node
 * @kset: The kset that represents this node.
 * @node: In the event where a sysfs manager node is placed at the root of the
 * device tree, this list_head reference is placed into the sysfs manager list.
 */
struct sysfs_mgr_node {
	struct sysfs_mgr *mgr;
	struct kset kset;
	struct list_head node;
};

/*
 * struct sysfs_mgr - The container that manages sysfs nodes linked to a device
 *
 * Allows for the creation of nested sysfs node directories using a format similar
 * to device attributes. Useful for representing complex devices whose components
 * are not subdevices.
 *
 * @device: A reference to the device who is being managed by this manager.
 * @list: A list of all of the directories stored under the device's root sysfs
 * directory. Since devices only have a kobject and not a kset, the manager must
 * track what sysfs_mgr_nodes have been added to the root device.
 * @list_lock: The lock that protects access to the list of sysfs manager nodes.
 */
struct sysfs_mgr {
	struct device *device;
	struct list_head list;
	spinlock_t list_lock; /* Controls access to the list of sysfs manager nodes */
};

struct sysfs_mgr_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device *dev, struct sysfs_mgr_node *node,
			struct sysfs_mgr_attribute *attr, char *buf);
	ssize_t (*store)(struct device *dev, struct sysfs_mgr_node *node,
			 struct sysfs_mgr_attribute *attr, const char *buf,
			 size_t count);
};

#define SYSFS_MGR_ATTR_RW(_name) \
	struct sysfs_mgr_attribute sysfs_mgr_attr_##_name = __ATTR_RW(_name)
#define SYSFS_MGR_ATTR_RO(_name) \
	struct  sysfs_mgr_attribute sysfs_mgr_attr_##_name = __ATTR_RO(_name)
#define SYSFS_MGR_ATTR_WO(_name) \
	struct sysfs_mgr_attribute sysfs_mgr_attr_##_name = __ATTR_WO(_name)

__must_check struct sysfs_mgr *sysfs_mgr_init(struct device *device);

void sysfs_mgr_cleanup(struct sysfs_mgr *mgr);

__must_check int sysfs_mgr_generate_directory(struct sysfs_mgr *mgr,
					      struct sysfs_mgr_node *parent,
					      const struct attribute_group *grp,
					      struct sysfs_mgr_node *node,
					      const char *name);

void sysfs_mgr_remove_directory(struct sysfs_mgr *mgr, struct sysfs_mgr_node *dir_ref);

__must_check int sysfs_mgr_generate_link(struct sysfs_mgr *mgr,
					 struct sysfs_mgr_node *parent,
					 struct sysfs_mgr_node *target,
					 const char *name);

void sysfs_mgr_remove_link(struct sysfs_mgr *mgr,
			   struct sysfs_mgr_node *parent,
			   const char *name);

#endif /* SYSFS_MGR_H */
