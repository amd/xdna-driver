// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "amdxdna_cbuf.h"
#include "amdxdna_debugfs.h"
#include "amdxdna_dpt.h"
#include "amdxdna_pm.h"

#include <drm/drm_file.h>
#include <linux/cleanup.h>
#include <linux/debugfs.h>
#include <linux/pm_runtime.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/uaccess.h>

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

static ssize_t amdxdna_carveout_write(struct file *file, const char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct amdxdna_dev *xdna = file_to_xdna(file);
	char kbuf[128];
	u64 size, addr;
	char *sep;
	int ret;

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	strim(kbuf);
	XDNA_DBG(xdna, "Trying to set carveout to %s", kbuf);

	sep = strchr(kbuf, '@');
	if (!sep)
		return -EINVAL;
	*sep = '\0';
	sep++;

	ret = kstrtou64(kbuf, 0, &size);
	if (ret)
		return ret;

	ret = kstrtou64(sep, 0, &addr);
	if (ret)
		return ret;

	/* Sanity check the addr and size. */
	if (!size)
		return -EINVAL;
	if (!IS_ALIGNED(addr, PAGE_SIZE) || !IS_ALIGNED(size, PAGE_SIZE))
		return -EINVAL;

	guard(mutex)(&xdna->dev_lock);

	ret = amdxdna_carveout_init(xdna, addr, size);
	if (ret)
		return ret;

	return count;
}

static int amdxdna_carveout_show(struct seq_file *m, void *unused)
{
	struct amdxdna_dev *xdna = m->private;
	u64 addr, size;

	guard(mutex)(&xdna->dev_lock);
	amdxdna_get_carveout_conf(xdna, &addr, &size);
	seq_printf(m, "0x%llx@0x%llx\n", size, addr);
	return 0;
}

/*
 * Input/output format: <carveout_size>@<carveout_address>
 */
AMDXDNA_DBGFS_FOPS(carveout, amdxdna_carveout_show, amdxdna_carveout_write);

/*
 * The DPT (fw_log/fw_trace) framework lives in amdxdna_dpt.o, which is only
 * built for the PCI (aie2/aie4) backends; VE2 (AUX) does not implement it
 * yet. Keep these nodes out of the AUX build rather than pulling amdxdna_dpt.o
 * (and its aie.o dependency, which is not AUX-safe) into it.
 */
#ifndef AMDXDNA_AUX
/*
 * fw_log_level: enable/disable firmware logging or change verbosity.
 * Write 0 to disable; 1..AMDXDNA_DPT_FW_LOG_LEVEL_MAX-1 to enable/relevel.
 * Read prints the current level (0 if inactive).
 */
static ssize_t fw_log_level_write(struct file *file, const char __user *ptr,
				  size_t len, loff_t *off)
{
	struct amdxdna_dev *xdna = file_to_xdna(file);
	u32 level;
	int ret;

	ret = kstrtouint_from_user(ptr, len, 0, &level);
	if (ret)
		return ret;

	guard(mutex)(&xdna->dev_lock);

	/*
	 * (Re)configuring firmware logging exchanges a message with the
	 * firmware, so the device must be awake. On an idle device runtime PM
	 * has suspended it (and the DPT), which would otherwise fail the write
	 * with -EBUSY; resume it for the duration of the config and let it
	 * autosuspend again afterwards.
	 */
	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		return ret;

	ret = amdxdna_fw_log_set_state(xdna, level);
	amdxdna_pm_suspend_put(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Failed to set FW log level %u: %d", level, ret);
		return ret;
	}

	return len;
}

static int fw_log_level_show(struct seq_file *m, void *unused)
{
	struct amdxdna_dev *xdna = m->private;
	struct amdxdna_dpt *dpt;
	u32 level = 0;
	int idx;

	dpt = amdxdna_dpt_enter_kind(xdna, AMDXDNA_DPT_FW_LOG, &idx);
	if (dpt) {
		level = READ_ONCE(dpt->config);
		amdxdna_dpt_exit_kind(xdna, idx);
	}

	seq_printf(m, "%u\n", level);
	return 0;
}

AMDXDNA_DBGFS_FOPS(fw_log_level, fw_log_level_show, fw_log_level_write);

/*
 * fw_log_dump_to_dmesg: toggle kernel-side streaming of FW log entries to
 * dmesg. Returns -EINVAL if FW logging is not ACTIVE.
 */
static ssize_t fw_log_dump_to_dmesg_write(struct file *file, const char __user *ptr,
					  size_t len, loff_t *off)
{
	struct amdxdna_dev *xdna = file_to_xdna(file);
	struct amdxdna_dpt *dpt;
	bool dump;
	int ret;

	ret = kstrtobool_from_user(ptr, len, &dump);
	if (ret)
		return ret;

	guard(mutex)(&xdna->dev_lock);

	/*
	 * Enabling/disabling the dmesg stream touches the DPT poll timer and
	 * buffer, so the device (and DPT) must be resumed first; an idle
	 * device is runtime-suspended with the DPT in SUSPENDED state. Resume
	 * for the operation and let it autosuspend again afterwards.
	 */
	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		return ret;

	dpt = rcu_dereference_protected(xdna->fw_log,
					lockdep_is_held(&xdna->dev_lock));
	if (!dpt || READ_ONCE(dpt->status) != AMDXDNA_DPT_ACTIVE) {
		amdxdna_pm_suspend_put(xdna);
		XDNA_ERR(xdna, "FW logging is not active");
		return -EINVAL;
	}

	ret = amdxdna_dpt_dump_to_dmesg(dpt, dump);
	amdxdna_pm_suspend_put(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Failed to %s FW log dmesg: %d",
			 dump ? "enable" : "disable", ret);
		return ret;
	}

	return len;
}

static int fw_log_dump_to_dmesg_show(struct seq_file *m, void *unused)
{
	struct amdxdna_dev *xdna = m->private;
	struct amdxdna_dpt *dpt;
	bool dump = false;
	int idx;

	dpt = amdxdna_dpt_enter_kind(xdna, AMDXDNA_DPT_FW_LOG, &idx);
	if (dpt) {
		dump = READ_ONCE(dpt->dump_to_dmesg);
		amdxdna_dpt_exit_kind(xdna, idx);
	}

	seq_printf(m, "%d\n", dump ? 1 : 0);
	return 0;
}

AMDXDNA_DBGFS_FOPS(fw_log_dump_to_dmesg, fw_log_dump_to_dmesg_show,
		   fw_log_dump_to_dmesg_write);
#endif /* !AMDXDNA_AUX */

static const struct {
	const char *name;
	const struct file_operations *fops;
	umode_t mode;
} amdxdna_dbgfs_files[] = {
	AMDXDNA_DBGFS_FILE(carveout, 0600),
#ifndef AMDXDNA_AUX
	AMDXDNA_DBGFS_FILE(fw_log_level, 0600),
	AMDXDNA_DBGFS_FILE(fw_log_dump_to_dmesg, 0600),
#endif
};

void amdxdna_debugfs_init(struct amdxdna_dev *xdna)
{
	struct drm_minor *minor = xdna->ddev.accel;
	int i;

	/*
	 * It should be okay that debugfs fails to init.
	 * We rely on DRM framework to finish debugfs.
	 */
	for (i = 0; i < ARRAY_SIZE(amdxdna_dbgfs_files); i++) {
		debugfs_create_file(amdxdna_dbgfs_files[i].name,
				    amdxdna_dbgfs_files[i].mode,
				    minor->debugfs_root,
				    xdna,
				    amdxdna_dbgfs_files[i].fops);
	}

	if (xdna->dev_info->ops->debugfs_init)
		xdna->dev_info->ops->debugfs_init(xdna);
}
