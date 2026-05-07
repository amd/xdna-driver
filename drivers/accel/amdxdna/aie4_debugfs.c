// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <drm/drm_file.h>
#include <linux/debugfs.h>
#include <linux/pm_runtime.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "amdxdna_cbuf.h"
#include "amdxdna_debugfs.h"
#include "aie4_pci.h"
#include "aie4_msg_priv.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_mailbox_helper.h"

#define _DBGFS_FOPS(_open, _release, _write) \
{ \
	.owner = THIS_MODULE, \
	.open = _open, \
	.read = seq_read, \
	.llseek = seq_lseek, \
	.release = _release, \
	.write = _write, \
}

#define AMDXDNA_DBGFS_FOPS(_name, _show, _write) \
	static int amdxdna_dbgfs_##_name##_open(struct inode *inode, struct file *file) \
	{ \
		return single_open(file, _show, inode->i_private); \
	} \
	static int amdxdna_dbgfs_##_name##_release(struct inode *inode, struct file *file) \
	{ \
		return single_release(inode, file); \
	} \
	static const struct file_operations amdxdna_fops_##_name = \
		_DBGFS_FOPS(amdxdna_dbgfs_##_name##_open, amdxdna_dbgfs_##_name##_release, _write)

#define AMDXDNA_DBGFS_FILE(_name, _mode) { #_name, &amdxdna_fops_##_name, _mode }

#define file_to_xdna(file) (((struct seq_file *)(file)->private_data)->private)

static int amdxdna_iommu_bypass_show(struct seq_file *m, void *unused)
{
	return 0;
}

static ssize_t amdxdna_iommu_bypass_write(struct file *file, const char __user *buf,
					  size_t count, loff_t *ppos)
{
	DECLARE_AIE_MSG(aie4_msg_echo, AIE4_MSG_OP_ECHO);
	struct amdxdna_dev *xdna = file_to_xdna(file);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	char kbuf[32];
	u8 val;
	int ret;

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	strim(kbuf);

	XDNA_DBG(xdna, "Trying to set iommu_bypass mode to %s", kbuf);

	ret = kstrtou8(kbuf, 0, &val);
	if (ret)
		return ret;

	if (!val)
		return count;

	XDNA_DBG(xdna, "Setting iommu_bypass mode to %d", val);

#define MAKE_MAGIC(a, b, c, d)  ((u32)((a) << 24 | (b) << 16 | (c) << 8 | (d)))
	req.val1 = MAKE_MAGIC('B', 'Y', 'P', 'A');
	req.val2 = MAKE_MAGIC('M', 'A', 'G', 'C');

	guard(mutex)(&xdna->dev_lock);
	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(xdna, "echo failed: %d", ret);

	if (req.val1 == resp.val1 &&
	    req.val2 == resp.val2)
		XDNA_INFO(xdna, "echo finished, response correct value.");
	else
		XDNA_WARN(xdna, "echo finished, expect: 0x%x,0x%x, got: 0x%x,0x%x",
			  req.val1, req.val1, resp.val1, resp.val2);

	return count;
}

/*
 * Input/output format: <carveout_size>@<carveout_address>
 */
AMDXDNA_DBGFS_FOPS(iommu_bypass, amdxdna_iommu_bypass_show, amdxdna_iommu_bypass_write);

static const struct {
	const char *name;
	const struct file_operations *fops;
	umode_t mode;
} aie4_dbgfs_files[] = {
	AMDXDNA_DBGFS_FILE(iommu_bypass, 0200),
};

void aie4_debugfs_init(struct amdxdna_dev *xdna)
{
	struct drm_minor *minor = xdna->ddev.accel;
	int i;

	for (i = 0; i < ARRAY_SIZE(aie4_dbgfs_files); i++) {
		debugfs_create_file(aie4_dbgfs_files[i].name,
				    aie4_dbgfs_files[i].mode,
				    minor->debugfs_root,
				    xdna,
				    aie4_dbgfs_files[i].fops);
	}
}
