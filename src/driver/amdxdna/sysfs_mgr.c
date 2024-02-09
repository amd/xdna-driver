// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#include "sysfs_mgr.h"

#include <linux/slab.h>

#define SYSFS_MGR_ERR(mgr, fmt, args...)	dev_err((mgr)->device, "%s: "fmt, __func__, ##args)
#define SYSFS_MGR_DBG(mgr, fmt, args...)	dev_dbg((mgr)->device, fmt, ##args)

static ssize_t
sysfs_mgr_show(struct kobject *kobj,
	       struct attribute *attr,
	       char *buf)
{
	struct sysfs_mgr_attribute *sysfs_mgr_attr;
	struct sysfs_mgr_node *node;
	struct kset *kset;

	kset = container_of(kobj, struct kset, kobj);
	node = container_of(kset, struct sysfs_mgr_node, kset);
	sysfs_mgr_attr = container_of(attr, struct sysfs_mgr_attribute, attr);

	if (!sysfs_mgr_attr || !node || !node->mgr) {
		SYSFS_MGR_ERR(node->mgr, "Malformed sysfs_mgr_node: %s", kobj->name);
		return -EIO;
	}

	if (!sysfs_mgr_attr->show)
		return -EIO;

	return sysfs_mgr_attr->show(node->mgr->device, node, sysfs_mgr_attr, buf);
}

static ssize_t
sysfs_mgr_store(struct kobject *kobj,
		struct attribute *attr,
		const char *buf,
		size_t count)
{
	struct sysfs_mgr_attribute *sysfs_mgr_attr;
	struct sysfs_mgr_node *node;
	struct kset *kset;

	kset = container_of(kobj, struct kset, kobj);
	node = container_of(kset, struct sysfs_mgr_node, kset);
	sysfs_mgr_attr = container_of(attr, struct sysfs_mgr_attribute, attr);

	if (!sysfs_mgr_attr || !node || !node->mgr) {
		SYSFS_MGR_ERR(node->mgr, "Malformed sysfs_mgr_node: %s", kobj->name);
		return -EIO;
	}

	if (!sysfs_mgr_attr->show)
		return -EIO;

	return sysfs_mgr_attr->store(node->mgr->device, node, sysfs_mgr_attr, buf, count);
}

static const struct sysfs_ops sysfs_mgr_ops = { /* All sysfs_mgr_nodes will use these operations */
	.show = sysfs_mgr_show,
	.store = sysfs_mgr_store,
};

/*
 * sysfs_mgr_node_release - The cleanup function for a sysfs_mgr_node
 *
 * @kobj: The kobj of the sysfs_mgr_node being released
 *
 * "Automatically" called when the number of references to a sysfs_mgr_node's
 * kset hits 0. Note that kset_unregister will automatically delete all
 * assigned attribute files. Since sysfs_mgr_remove_directory does that
 * already do not attempt to release any attributes here. Unless you want an
 * oops!
 */
static void
sysfs_mgr_node_release(struct kobject *kobj)
{
	struct sysfs_mgr_node *node;
	struct kobject *entry_kobj;
	struct kset *entry_kset;
	struct list_head *tmp;
	struct list_head *el;
	struct kset *kset;

	kset = container_of(kobj, struct kset, kobj);
	node = container_of(kset, struct sysfs_mgr_node, kset);

	spin_lock(&kset->list_lock);
	list_for_each_prev_safe(el, tmp, &kset->list) {
		list_del_init(el);
		spin_unlock(&kset->list_lock);
		entry_kobj = container_of(el, struct kobject, entry);
		entry_kset = container_of(entry_kobj, struct kset, kobj);
		kset_unregister(entry_kset);
		spin_lock(&kset->list_lock);
	}
	spin_unlock(&kset->list_lock);

	node->mgr = NULL;
}

static const struct kobj_type sysfs_mgr_node_ktype = {
	.release = sysfs_mgr_node_release,
	.sysfs_ops = &sysfs_mgr_ops,
};

/*
 * sysfs_mgr_create_group - Adds an attribute group to a sysfs manager node.
 *
 * @sysfs_mgr: The sysfs manager in charge of the given node.
 * @node: A reference to a node.
 * @grp: A reference to the attributes to add to the given node.
 *
 * This function calls sysfs_create_group()
 *
 * This function adds the given attribute group to the given node.
 */
__must_check static int
sysfs_mgr_create_group(struct sysfs_mgr *mgr,
		       struct sysfs_mgr_node *node,
		       const struct attribute_group *grp)
{
	int res;

	res = sysfs_create_group(&node->kset.kobj, grp);
	if (res)
		SYSFS_MGR_ERR(mgr, "%s", "Could not create sysfs_mgr_node attributes");

	return res;
}

/*
 * sysfs_mgr_init - Initialize a sysfs manager
 *
 * @device: The device that will be represented via the sysfs manager.
 *
 * Return: An initialized sysfs manager pointer
 *
 * This function initializes the given sysfs manager such that nodes added to the root populate
 * in the same directory as the given device's root sysfs directory.
 */
struct sysfs_mgr *
sysfs_mgr_init(struct device *device)
{
	struct sysfs_mgr *mgr;

	mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);
	if (!mgr)
		return ERR_PTR(-ENOMEM);

	mgr->device = device;
	INIT_LIST_HEAD(&mgr->list);
	spin_lock_init(&mgr->list_lock);
	return mgr;
}

/*
 * sysfs_mgr_cleanup - Cleanup all sysfs manager resources including children.
 *
 * @sysfs_mgr: The sysfs manager.
 *
 * This function cleans up all children associated with the given sysfs manager
 * and its own resources.
 */
void sysfs_mgr_cleanup(struct sysfs_mgr *mgr)
{
	struct sysfs_mgr_node *entry_node;
	struct list_head *tmp;
	struct list_head *el;

	if (!mgr)
		return;

	spin_lock(&mgr->list_lock);
	list_for_each_prev_safe(el, tmp, &mgr->list) {
		list_del_init(el);
		spin_unlock(&mgr->list_lock);
		entry_node = container_of(el, struct sysfs_mgr_node, node);
		kset_unregister(&entry_node->kset);
		spin_lock(&mgr->list_lock);
	}
	spin_unlock(&mgr->list_lock);

	kfree(mgr);
}

/*
 * sysfs_mgr_init_and_add_directory - Initializes and adds a new node to the parent node.
 *
 * @sysfs_mgr: The sysfs manager in charge of both the new and parent node.
 * @parent: A reference to the parent node. Can be NULL.
 * @node: A reference to the node that will represent the new directory.
 * @name: The name for the new directory.
 *
 * Return: An initialized sysfs_mgr node
 *
 * This function intializes the given sysfs manager node reference adds the
 * node to the parent node if the given parent node is NULL.
 */
__must_check static int
sysfs_mgr_init_and_add_directory(struct sysfs_mgr *mgr,
				 struct sysfs_mgr_node *parent,
				 struct sysfs_mgr_node *node,
				 const char *name)
{
	struct kset *kset;
	int res;

	node->mgr = mgr;
	INIT_LIST_HEAD(&node->node);

	kset = &node->kset;
	kobject_set_name(&kset->kobj, "%s", name);

	if (!parent) {
		kset->kobj.parent = &mgr->device->kobj;
	} else {
		kset->kobj.parent = &parent->kset.kobj;
		/* During kset register the new kset will be added to the parent kset */
		kset->kobj.kset = &parent->kset;
	}

	kset->kobj.ktype = &sysfs_mgr_node_ktype;
	res = kset_register(kset);
	if (res) {
		SYSFS_MGR_ERR(mgr, "Could not register sysfs_mgr kset for: %s. Res: %d",
			      name, res);
		return res;
	}

	/* Node can only be added to the root list after being registered */
	if (!parent) {
		spin_lock(&mgr->list_lock);
		list_add_tail(&node->node, &mgr->list);
		spin_unlock(&mgr->list_lock);
	}

	return res;
}

/*
 * sysfs_mgr_generate_directory - Initializes a node, adds the new node to the
 * parent node, and, adds attributes to the new node.
 *
 * @sysfs_mgr: The sysfs manager in charge of both the new and parent node.
 * @parent: A reference to the parent node. Can be NULL.
 * @grp: A reference to the attributes to add to the given node. Can be NULL.
 * @node: A reference to the node that will represent the new directory.
 * @name: The name for the new directory.
 *
 * When no attributes need to be added to a directory, grp should be NULL.
 */
int
sysfs_mgr_generate_directory(struct sysfs_mgr *mgr,
			     struct sysfs_mgr_node *parent,
			     const struct attribute_group *grp,
			     struct sysfs_mgr_node *node,
			     const char *name)
{
	int res;

	res = sysfs_mgr_init_and_add_directory(mgr, parent, node, name);
	if (res) {
		SYSFS_MGR_ERR(mgr, "Failed to generate directory: %s. Res: %d", name, res);
		return res;
	}

	/* Exit early if there are no attributes */
	if (!grp)
		return res;

	res = sysfs_mgr_create_group(mgr, node, grp);
	if (res) {
		SYSFS_MGR_ERR(mgr, "Failed to add group attributes for node: %s. Res: %d",
			      name, res);
		sysfs_mgr_remove_directory(mgr, node);
		return res;
	}
	return res;
}

/*
 * sysfs_mgr_generate_link - Initializes a symbolic link by creating adds a node under the
 * parent node that points to the target node.
 *
 * @sysfs_mgr: The sysfs manager in charge of both the new and parent node.
 * @parent: A reference to the parent node. Can be NULL.
 * @target: A reference to the node that will the link will point to.
 * @name: The name for the new link.
 */
int
sysfs_mgr_generate_link(struct sysfs_mgr *mgr,
			struct sysfs_mgr_node *parent,
			struct sysfs_mgr_node *target,
			const char *name)
{
	struct kobject *valid_parent;
	int res;

	if (!parent)
		valid_parent = &mgr->device->kobj;
	else
		valid_parent = &parent->kset.kobj;

	res = sysfs_create_link(valid_parent, &target->kset.kobj, name);
	if (res) {
		SYSFS_MGR_ERR(mgr, "Failed creating symlink %s. Target: %s. Res: %d",
			      name, target->kset.kobj.name, res);
		return res;
	}

	return res;
}

/*
 * sysfs_mgr_remove_link - Removes a symbolic link from under the parent node.
 *
 * @sysfs_mgr: The sysfs manager in charge of both the new and parent node.
 * @parent: A reference to the parent node. Can be NULL.
 * @name: The name for the link to remove.
 */
void
sysfs_mgr_remove_link(struct sysfs_mgr *mgr,
		      struct sysfs_mgr_node *parent,
		      const char *name)
{
	struct kobject *valid_parent;

	if (!parent)
		valid_parent = &mgr->device->kobj;
	else
		valid_parent = &parent->kset.kobj;

	sysfs_remove_link(valid_parent, name);
}

/*
 * sysfs_mgr_remove_directory - Cleanup all sysfs manager node resources including children.
 *
 * @sysfs_mgr: The sysfs manager in charge of the given node.
 * @node: A reference to a node that represents a directory.
 *
 * This function cleans up all children associated with the given node and its own resources.
 */
void
sysfs_mgr_remove_directory(struct sysfs_mgr *mgr,
			   struct sysfs_mgr_node *node)
{
	/*
	 * The sysfs manager does not register a kset for root directories to
	 * link against when registering their own ksets. As a result they would
	 * not be removed from the appropriate list via `kset_unregister`. So we
	 * must remove the enbtry ourselves only when dealing with directories
	 * places at the root.
	 */
	if (node->kset.kobj.parent == &mgr->device->kobj) {
		spin_lock(&mgr->list_lock);
		list_del_init(&node->node);
		spin_unlock(&mgr->list_lock);
	}

	kset_unregister(&node->kset);
}
