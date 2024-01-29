// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2022-2024 Advanced Micro Devices, Inc.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/string.h>
#include <linux/completion.h>
#include <drm/drm_debugfs.h>

#include "ipu_common.h"
#include "ipu_msg_priv.h"
#include "ipu_pci.h"

#if defined(CONFIG_DEBUG_FS)
#define SIZE            31

#define TX_TIMEOUT 2000 /* miliseconds */
#define RX_TIMEOUT 5000 /* miliseconds */

#define _DBGFS_FOPS(_open, _write) \
{ \
	.owner = THIS_MODULE, \
	.open = _open, \
	.read = seq_read, \
	.llseek = seq_lseek, \
	.release = single_release, \
	.write = _write, \
}

#define _DBGFS_FOPS_WO(_write) \
{ \
	.owner = THIS_MODULE, \
	.open = simple_open, \
	.llseek = default_llseek, \
	.write = _write, \
}

#define IPU_DBGFS_FOPS(_name, _show, _write) \
	static int ipu_dbgfs_##_name##_open(struct inode *inode, struct file *file) \
{ \
	return single_open(file, _show, inode->i_private); \
} \
const struct file_operations ipu_fops_##_name = \
_DBGFS_FOPS(ipu_dbgfs_##_name##_open, _write)

#define IPU_DBGFS_FOPS_WO(_name, _write) \
	const struct file_operations ipu_fops_##_name = _DBGFS_FOPS_WO(_write)

#define IPU_DBGFS_FILE(_name, _mode) { #_name, &ipu_fops_##_name, _mode }

#define file_to_idev_wo(file) \
	((file)->private_data)

#define file_to_idev_rw(file) \
	(((struct seq_file *)(file)->private_data)->private)

static ssize_t ipu_clock_write(struct file *file, const char __user *ptr,
			       size_t len, loff_t *off)
{
	struct ipu_device *idev = file_to_idev_rw(file);
	u32 val;
	int ret;

	ret = kstrtouint_from_user(ptr, len, 10, &val);
	if (ret) {
		XDNA_ERR(idev->xdna, "Invalid input value: %d", val);
		return ret;
	}

	ipu_smu_set_mpipu_clock_freq(idev, val);
	return len;
}

static int ipu_clock_show(struct seq_file *m, void *unused)
{
	return 0;
}

IPU_DBGFS_FOPS(ipuclock, ipu_clock_show, ipu_clock_write);

static ssize_t ipu_pasid_write(struct file *file, const char __user *ptr,
			       size_t len, loff_t *off)
{
	struct ipu_device *idev = file_to_idev_rw(file);
	u32 val;
	int ret;

	ret = kstrtouint_from_user(ptr, len, 10, &val);
	if (ret) {
		XDNA_ERR(idev->xdna, "Invalid input value: %d", val);
		return ret;
	}

	ret = ipu_assign_mgmt_pasid(idev, val);
	if (ret) {
		XDNA_ERR(idev->xdna, "Assigning pasid: %d failed, ret: %d", val, ret);
		return ret;
	}
	return len;
}

static int ipu_pasid_show(struct seq_file *m, void *unused)
{
	return 0;
}

IPU_DBGFS_FOPS(pasid, ipu_pasid_show, ipu_pasid_write);

static ssize_t ipu_power_state_write(struct file *file, const char __user *ptr,
				     size_t len, loff_t *off)
{
	struct ipu_device *idev = file_to_idev_rw(file);
	char input[SIZE + 1];
	int ret;

	if (len > SIZE) {
		XDNA_ERR(idev->xdna, "Length %zu  of the buffer exceeds size %d", len, SIZE);
		return -EINVAL;
	}

	ret = copy_from_user(input, ptr, len);
	if (ret) {
		XDNA_ERR(idev->xdna, "Invalid input: %s", input);
		return ret;
	}

	if (!strncmp(input, "on", strlen("on"))) {
		ret = ipu_smu_set_power_on(idev);
	} else if (!strncmp(input, "off", strlen("off"))) {
		ret = ipu_smu_set_power_off(idev);
	} else {
		XDNA_ERR(idev->xdna, "Invalid input: %s", input);
		return -EINVAL;
	}

	if (ret) {
		XDNA_ERR(idev->xdna, "IPU power %s failed", input);
		return -EINVAL;
	}

	XDNA_DBG(idev->xdna, "IPU power %s successful", input);
	return len;
}

static int ipu_power_state_show(struct seq_file *m, void *unused)
{
	return 0;
}

IPU_DBGFS_FOPS(powerstate, ipu_power_state_show, ipu_power_state_write);

static ssize_t ipu_state_write(struct file *file, const char __user *ptr,
			       size_t len, loff_t *off)
{
	struct ipu_device *idev = file_to_idev_rw(file);
	char input[SIZE + 1];
	int ret;

	if (len > SIZE) {
		XDNA_ERR(idev->xdna, "Length %zu of the buffer exceeds size %d", len, SIZE);
		return -EINVAL;
	}

	ret = copy_from_user(input, ptr, len);
	if (ret) {
		XDNA_ERR(idev->xdna, "Invalid input: %s", input);
		return ret;
	}

	if (!strncmp(input, "suspend", strlen("suspend"))) {
		ret = ipu_suspend_fw(idev);
	} else if (!strncmp(input, "resume", strlen("resume"))) {
		ret = ipu_resume_fw(idev);
	} else {
		XDNA_ERR(idev->xdna, "Invalid input: %s", input);
		return -EINVAL;
	}

	if (ret) {
		XDNA_ERR(idev->xdna, "IPU %s failed", input);
		return -EINVAL;
	}

	XDNA_DBG(idev->xdna, "IPU %s succeeded", input);
	return len;
}

static int ipu_state_show(struct seq_file *m, void *unused)
{
	return 0;
}

IPU_DBGFS_FOPS(state, ipu_state_show, ipu_state_write);

static ssize_t ipu_dbgfs_hclock_write(struct file *file, const char __user *ptr,
				      size_t len, loff_t *off)
{
	struct ipu_device *idev = file_to_idev_wo(file);
	u32 val;
	int ret;

	ret = kstrtouint_from_user(ptr, len, 10, &val);
	if (ret) {
		XDNA_ERR(idev->xdna, "Invalid input val: %d", val);
		return ret;
	}

	ipu_smu_set_hclock_freq(idev, val);

	return len;
}

IPU_DBGFS_FOPS_WO(hclock, ipu_dbgfs_hclock_write);

static int test_case01(struct ipu_device *idev)
{
	int ret;

	if (!idev->xdna->mgmt_chann) {
		XDNA_ERR(idev->xdna, "mgmt chann is not alive??");
		return -EINVAL;
	}

	XDNA_INFO(idev->xdna, "Starting IPU health check");
	ret = ipu_check_header_hash(idev);
	if (ret) {
		XDNA_ERR(idev->xdna, "IPU health check failed: ret=%d", ret);
		return ret;
	}

	XDNA_INFO(idev->xdna, "IPU health check passed");
	return 0;
}

static void test_case02_cb(void *handle, const u32 *data, size_t size)
{
	struct completion *comp = handle;

	complete(comp);
}

static int test_case02(struct ipu_device *idev, u32 argc, const u32 *args)
{
	struct xdna_mailbox_msg msg;
	DECLARE_COMPLETION(comp);
	size_t req_bytes;
	u32 cnt = 1;
	u32 req_size;
	u32 resp_size;
	u32 pattern;
	u32 *data;
	int ret;
	int i;

	if (argc < 4) {
		XDNA_ERR(idev->xdna, "Too few parameters");
		return -EINVAL;
	}

	req_size = args[1];
	resp_size = args[2];
	pattern = args[3];
	if (argc >= 5)
		cnt = args[4];

	if (req_size < 2 || req_size > 0x400) {
		XDNA_ERR(idev->xdna, "Invalid request size %d", req_size);
		return -EINVAL;
	}

	if (!resp_size || resp_size > 28) {
		XDNA_ERR(idev->xdna, "Invalid resp size %d", resp_size);
		return -EINVAL;
	}

	XDNA_DBG(idev->xdna, "test case 2 start");
	XDNA_DBG(idev->xdna, "req_size %d, resp_size %d, pattern 0x%x",
		 req_size, resp_size, pattern);

	req_bytes = req_size * sizeof(u32);
	data = vmalloc(req_bytes);
	if (!data)
		return -ENOMEM;

	data[0] = resp_size;
	for (i = 1; i < req_size; i++)
		data[i] = pattern;

	msg.opcode = 0x101010;
	msg.handle = &comp;
	msg.notify_cb = test_case02_cb;
	msg.send_data = (u8 *)data;
	msg.send_size = req_bytes;

	for (i = 0; i < cnt; i++) {
		ret = xdna_mailbox_send_msg(idev->xdna->mgmt_chann, &msg, TX_TIMEOUT);
		if (ret) {
			XDNA_ERR(idev->xdna, "Send message failed, ret %d", ret);
			break;
		}
	}

	for (i = 0; i < cnt; i++) {
		ret = wait_for_completion_timeout(&comp, msecs_to_jiffies(RX_TIMEOUT));
		if (!ret) {
			XDNA_ERR(idev->xdna, "wait for completion timeout");
			ret = -ETIME;
			break;
		}
	}

	vfree(data);
	XDNA_DBG(idev->xdna, "test case 2 completed, ret %d", (ret > 0) ? 0 : ret);
	return ret;
}

#define IPUTEST_MAX_PARAM 5
static ssize_t ipu_dbgfs_iputest(struct file *file, const char __user *ptr,
				 size_t len, loff_t *off)
{
	struct ipu_device *idev = file_to_idev_rw(file);
	char *kern_buff, *tmp_buff, *sub_str;
	u32 args[IPUTEST_MAX_PARAM];
	int argc = 0;
	int ret;

	kern_buff = memdup_user_nul(ptr, len);
	if (IS_ERR(kern_buff))
		return PTR_ERR(kern_buff);
	tmp_buff = kern_buff;

	while ((sub_str = strsep(&tmp_buff, " "))) {
		if (argc == IPUTEST_MAX_PARAM) {
			XDNA_ERR(idev->xdna, "MAX arguments %d", argc);
			break;
		}

		ret = kstrtou32(sub_str, 0, &args[argc]);
		if (ret) {
			XDNA_ERR(idev->xdna, "Wrong parameter");
			ret = -EINVAL;
			goto free_and_out;
		}
		argc++;
	}
	XDNA_DBG(idev->xdna, "Got %d parameters\n", argc);

	/* args[0] is test case ID */
	switch (args[0]) {
	case 1:
		ret = test_case01(idev);
		break;
	case 2:
		ret = test_case02(idev, argc, args);
		break;
	case 3:
		ret = ipu_self_test(idev);
		break;
	default:
		XDNA_ERR(idev->xdna, "Unknown test case ID %d\n", args[0]);
	}

free_and_out:
	kfree(kern_buff);
	return (ret) ? ret : len;
}

static int ipu_dbgfs_iputest_show(struct seq_file *m, void *unused)
{
	seq_puts(m, "iputest usage:\n");
	seq_puts(m, "\techo id [args] > <debugfs_path>/dri/<render_id>/iputest\n");
	seq_puts(m, "\t\tid - test case id (1 - 2), bad id will be ignore\n");
	seq_puts(m, "\t\targs - arguments for test case, optional\n");
	seq_puts(m, "\n");
	seq_puts(m, "test case 1 usage:\n");
	seq_puts(m, "\techo 1 > <iputest file>\n");
	seq_puts(m, "\n");
	seq_puts(m, "test case 2 usage:\n");
	seq_puts(m, "\techo 2 msg_len resp_len pattern [cnt] > <iputest file>\n");
	seq_puts(m, "\t\tmsg_len - messge length in words (>= 2)\n");
	seq_puts(m, "\t\tresp_len - response length in words (1 - 28)\n");
	seq_puts(m, "\t\tpattern - data to fill message and response\n");
	seq_puts(m, "\t\tcnt - send cnt messages without wait, optional (default 1)\n");

	return 0;
}

IPU_DBGFS_FOPS(iputest, ipu_dbgfs_iputest_show, ipu_dbgfs_iputest);

static const struct {
	const char *name;
	const struct file_operations *fops;
	umode_t mode;
} ipu_dbgfs_files[] = {
	IPU_DBGFS_FILE(iputest, 0400),
	IPU_DBGFS_FILE(hclock, 0400),
	IPU_DBGFS_FILE(ipuclock, 0600),
	IPU_DBGFS_FILE(pasid, 0600),
	IPU_DBGFS_FILE(state, 0600),
	IPU_DBGFS_FILE(powerstate, 0600),
};

/* only for ipu_debugfs_list */
#define seqf_to_xdna_dev(m) \
	to_xdna_dev(((struct drm_info_node *)(m)->private)->minor->dev)

static int
mpipu_ringbuf_show(struct seq_file *m, void *unused)
{
	struct ipu_device *idev = seqf_to_xdna_dev(m)->dev_handle;

	return xdna_mailbox_ringbuf_show(idev->xdna->mbox, m);
}

static int
mpipu_msg_queue_show(struct seq_file *m, void *unused)
{
	struct ipu_device *idev = seqf_to_xdna_dev(m)->dev_handle;

	return xdna_mailbox_info_show(idev->xdna->mbox, m);
}

static const struct drm_info_list ipu_debugfs_list[] = {
	{"ringbuf", mpipu_ringbuf_show, 0},
	{"msg_queues", mpipu_msg_queue_show, 0},
};

#define INFO_LIST_ENTRIES ARRAY_SIZE(ipu_debugfs_list)

void ipu_debugfs_init(struct ipu_device *idev)
{
	struct drm_minor *minor = idev->xdna->ddev.accel;
	int i;

	/*
	 * For debugfs APIs, it is expected that most callers
	 * should _ignore_ the errors returned.
	 * It should be okay that debugfs fails to init anyway.
	 *
	 * BTW, we rely on DRM framework to finish debugfs.
	 */
	for (i = 0; i < ARRAY_SIZE(ipu_dbgfs_files); i++) {
		debugfs_create_file(ipu_dbgfs_files[i].name,
				    ipu_dbgfs_files[i].mode,
				    minor->debugfs_root, idev,
				    ipu_dbgfs_files[i].fops);
	}

	/* DRM debugfs handles readonly files */
	drm_debugfs_create_files(ipu_debugfs_list, INFO_LIST_ENTRIES,
				 minor->debugfs_root, minor);
}
#else
void ipu_debugfs_init(struct ipu_device *idev)
{
}
#endif /* CONFIG_DEBUG_FS */
