// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/completion.h>
#include <drm/drm_debugfs.h>

#include "aie2_msg_priv.h"
#include "aie2_pci.h"

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

#define AIE2_DBGFS_FOPS(_name, _show, _write) \
	static int aie2_dbgfs_##_name##_open(struct inode *inode, struct file *file) \
{ \
	return single_open(file, _show, inode->i_private); \
} \
const struct file_operations aie2_fops_##_name = \
_DBGFS_FOPS(aie2_dbgfs_##_name##_open, _write)

#define AIE2_DBGFS_FOPS_WO(_name, _write) \
	const struct file_operations aie2_fops_##_name = _DBGFS_FOPS_WO(_write)

#define AIE2_DBGFS_FILE(_name, _mode) { #_name, &aie2_fops_##_name, _mode }

#define file_to_ndev_wo(file) \
	((file)->private_data)

#define file_to_ndev_rw(file) \
	(((struct seq_file *)(file)->private_data)->private)

static ssize_t aie2_clock_write(struct file *file, const char __user *ptr,
				size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = file_to_ndev_rw(file);
	u32 val;
	int ret;

	ret = kstrtouint_from_user(ptr, len, 10, &val);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Invalid input value: %d", val);
		return ret;
	}

	aie2_smu_set_mpnpu_clock_freq(ndev, val);
	return len;
}

static int aie2_clock_show(struct seq_file *m, void *unused)
{
	return 0;
}

AIE2_DBGFS_FOPS(npuclock, aie2_clock_show, aie2_clock_write);

static ssize_t aie2_pasid_write(struct file *file, const char __user *ptr,
				size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = file_to_ndev_rw(file);
	u32 val;
	int ret;

	ret = kstrtouint_from_user(ptr, len, 10, &val);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Invalid input value: %d", val);
		return ret;
	}

	ret = aie2_assign_mgmt_pasid(ndev, val);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Assigning pasid: %d failed, ret: %d", val, ret);
		return ret;
	}
	return len;
}

static int aie2_pasid_show(struct seq_file *m, void *unused)
{
	return 0;
}

AIE2_DBGFS_FOPS(pasid, aie2_pasid_show, aie2_pasid_write);

static ssize_t aie2_power_state_write(struct file *file, const char __user *ptr,
				      size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = file_to_ndev_rw(file);
	char input[SIZE + 1];
	int ret;

	if (len > SIZE) {
		XDNA_ERR(ndev->xdna, "Length %zu  of the buffer exceeds size %d", len, SIZE);
		return -EINVAL;
	}

	ret = copy_from_user(input, ptr, len);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Invalid input: %s", input);
		return ret;
	}

	if (!strncmp(input, "on", strlen("on"))) {
		ret = aie2_smu_set_power_on(ndev);
	} else if (!strncmp(input, "off", strlen("off"))) {
		ret = aie2_smu_set_power_off(ndev);
	} else {
		XDNA_ERR(ndev->xdna, "Invalid input: %s", input);
		return -EINVAL;
	}

	if (ret) {
		XDNA_ERR(ndev->xdna, "NPU power %s failed", input);
		return -EINVAL;
	}

	XDNA_DBG(ndev->xdna, "NPU power %s successful", input);
	return len;
}

static int aie2_power_state_show(struct seq_file *m, void *unused)
{
	return 0;
}

AIE2_DBGFS_FOPS(powerstate, aie2_power_state_show, aie2_power_state_write);

static ssize_t aie2_state_write(struct file *file, const char __user *ptr,
				size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = file_to_ndev_rw(file);
	char input[SIZE + 1];
	int ret;

	if (len > SIZE) {
		XDNA_ERR(ndev->xdna, "Length %zu of the buffer exceeds size %d", len, SIZE);
		return -EINVAL;
	}

	ret = copy_from_user(input, ptr, len);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Invalid input: %s", input);
		return ret;
	}

	if (!strncmp(input, "suspend", strlen("suspend"))) {
		mutex_lock(&ndev->xdna->dev_lock);
		ret = aie2_suspend_fw(ndev);
		mutex_unlock(&ndev->xdna->dev_lock);
	} else if (!strncmp(input, "resume", strlen("resume"))) {
		mutex_lock(&ndev->xdna->dev_lock);
		ret = aie2_resume_fw(ndev);
		mutex_unlock(&ndev->xdna->dev_lock);
	} else {
		XDNA_ERR(ndev->xdna, "Invalid input: %s", input);
		return -EINVAL;
	}

	if (ret) {
		XDNA_ERR(ndev->xdna, "NPU %s failed", input);
		return -EINVAL;
	}

	XDNA_DBG(ndev->xdna, "NPU %s succeeded", input);
	return len;
}

static int aie2_state_show(struct seq_file *m, void *unused)
{
	return 0;
}

AIE2_DBGFS_FOPS(state, aie2_state_show, aie2_state_write);

static ssize_t aie2_dbgfs_hclock_write(struct file *file, const char __user *ptr,
				       size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = file_to_ndev_wo(file);
	u32 val;
	int ret;

	ret = kstrtouint_from_user(ptr, len, 10, &val);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Invalid input val: %d", val);
		return ret;
	}

	aie2_smu_set_hclock_freq(ndev, val);

	return len;
}

AIE2_DBGFS_FOPS_WO(hclock, aie2_dbgfs_hclock_write);

static int test_case01(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	if (!ndev->mgmt_chann) {
		XDNA_ERR(ndev->xdna, "mgmt chann is not alive??");
		return -EINVAL;
	}

	XDNA_INFO(ndev->xdna, "Starting NPU health check");
	ret = aie2_check_protocol_version(ndev);
	if (ret) {
		XDNA_ERR(ndev->xdna, "NPU health check failed: ret=%d", ret);
		return ret;
	}

	XDNA_INFO(ndev->xdna, "NPU health check passed");
	return 0;
}

static int test_case02_cb(void *handle, const u32 *data, size_t size)
{
	struct completion *comp = handle;

	complete(comp);
	return 0;
}

static int test_case02(struct amdxdna_dev_hdl *ndev, u32 argc, const u32 *args)
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
		XDNA_ERR(ndev->xdna, "Too few parameters");
		return -EINVAL;
	}

	req_size = args[1];
	resp_size = args[2];
	pattern = args[3];
	if (argc >= 5)
		cnt = args[4];

	if (req_size < 2 || req_size > 0x400) {
		XDNA_ERR(ndev->xdna, "Invalid request size %d", req_size);
		return -EINVAL;
	}

	if (!resp_size || resp_size > 28) {
		XDNA_ERR(ndev->xdna, "Invalid resp size %d", resp_size);
		return -EINVAL;
	}

	XDNA_DBG(ndev->xdna, "test case 2 start");
	XDNA_DBG(ndev->xdna, "req_size %d, resp_size %d, pattern 0x%x",
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
		ret = xdna_mailbox_send_msg(ndev->mgmt_chann, &msg, TX_TIMEOUT);
		if (ret) {
			XDNA_ERR(ndev->xdna, "Send message failed, ret %d", ret);
			break;
		}
	}

	for (i = 0; i < cnt; i++) {
		ret = wait_for_completion_timeout(&comp, msecs_to_jiffies(RX_TIMEOUT));
		if (!ret) {
			XDNA_ERR(ndev->xdna, "wait for completion timeout");
			ret = -ETIME;
			break;
		}
	}

	vfree(data);
	XDNA_DBG(ndev->xdna, "test case 2 completed, ret %d", (ret > 0) ? 0 : ret);
	return ret;
}

#define NPUTEST_MAX_PARAM 5
static ssize_t aie2_dbgfs_nputest(struct file *file, const char __user *ptr,
				  size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = file_to_ndev_rw(file);
	char *kern_buff, *tmp_buff, *sub_str;
	u32 args[NPUTEST_MAX_PARAM];
	int argc = 0;
	int ret;

	kern_buff = memdup_user_nul(ptr, len);
	if (IS_ERR(kern_buff))
		return PTR_ERR(kern_buff);
	tmp_buff = kern_buff;

	while ((sub_str = strsep(&tmp_buff, " "))) {
		if (argc == NPUTEST_MAX_PARAM) {
			XDNA_ERR(ndev->xdna, "MAX arguments %d", argc);
			break;
		}

		ret = kstrtou32(sub_str, 0, &args[argc]);
		if (ret) {
			XDNA_ERR(ndev->xdna, "Wrong parameter");
			ret = -EINVAL;
			goto free_and_out;
		}
		argc++;
	}
	XDNA_DBG(ndev->xdna, "Got %d parameters\n", argc);

	mutex_lock(&ndev->xdna->dev_lock);
	/* args[0] is test case ID */
	switch (args[0]) {
	case 1:
		ret = test_case01(ndev);
		break;
	case 2:
		ret = test_case02(ndev, argc, args);
		break;
	case 3:
		ret = aie2_self_test(ndev);
		break;
	default:
		XDNA_ERR(ndev->xdna, "Unknown test case ID %d\n", args[0]);
	}
	mutex_unlock(&ndev->xdna->dev_lock);

free_and_out:
	kfree(kern_buff);
	return (ret) ? ret : len;
}

static int aie2_dbgfs_nputest_show(struct seq_file *m, void *unused)
{
	seq_puts(m, "nputest usage:\n");
	seq_puts(m, "\techo id [args] > <debugfs_path>/dri/<render_id>/nputest\n");
	seq_puts(m, "\t\tid - test case id (1 - 2), bad id will be ignore\n");
	seq_puts(m, "\t\targs - arguments for test case, optional\n");
	seq_puts(m, "\n");
	seq_puts(m, "test case 1 usage:\n");
	seq_puts(m, "\techo 1 > <nputest file>\n");
	seq_puts(m, "\n");
	seq_puts(m, "test case 2 usage:\n");
	seq_puts(m, "\techo 2 msg_len resp_len pattern [cnt] > <nputest file>\n");
	seq_puts(m, "\t\tmsg_len - messge length in words (>= 2)\n");
	seq_puts(m, "\t\tresp_len - response length in words (1 - 28)\n");
	seq_puts(m, "\t\tpattern - data to fill message and response\n");
	seq_puts(m, "\t\tcnt - send cnt messages without wait, optional (default 1)\n");

	return 0;
}

AIE2_DBGFS_FOPS(nputest, aie2_dbgfs_nputest_show, aie2_dbgfs_nputest);

const struct {
	const char *name;
	const struct file_operations *fops;
	umode_t mode;
} aie2_dbgfs_files[] = {
	AIE2_DBGFS_FILE(nputest, 0400),
	AIE2_DBGFS_FILE(hclock, 0400),
	AIE2_DBGFS_FILE(npuclock, 0600),
	AIE2_DBGFS_FILE(pasid, 0600),
	AIE2_DBGFS_FILE(state, 0600),
	AIE2_DBGFS_FILE(powerstate, 0600),
};

/* only for aie2_debugfs_list */
#define seqf_to_xdna_dev(m) \
	to_xdna_dev(((struct drm_info_node *)(m)->private)->minor->dev)

static int
aie2_ringbuf_show(struct seq_file *m, void *unused)
{
	struct amdxdna_dev_hdl *ndev = seqf_to_xdna_dev(m)->dev_handle;

	return xdna_mailbox_ringbuf_show(ndev->mbox, m);
}

static int
aie2_msg_queue_show(struct seq_file *m, void *unused)
{
	struct amdxdna_dev_hdl *ndev = seqf_to_xdna_dev(m)->dev_handle;

	return xdna_mailbox_info_show(ndev->mbox, m);
}

static const struct drm_info_list aie2_debugfs_list[] = {
	{"ringbuf", aie2_ringbuf_show, 0},
	{"msg_queues", aie2_msg_queue_show, 0},
};

#define INFO_LIST_ENTRIES ARRAY_SIZE(aie2_debugfs_list)

void aie2_debugfs_init(struct amdxdna_dev *xdna)
{
	struct drm_minor *minor = xdna->ddev.accel;
	int i;

	/*
	 * For debugfs APIs, it is expected that most callers
	 * should _ignore_ the errors returned.
	 * It should be okay that debugfs fails to init anyway.
	 *
	 * BTW, we rely on DRM framework to finish debugfs.
	 */
	for (i = 0; i < ARRAY_SIZE(aie2_dbgfs_files); i++) {
		debugfs_create_file(aie2_dbgfs_files[i].name,
				    aie2_dbgfs_files[i].mode,
				    minor->debugfs_root,
				    xdna->dev_handle,
				    aie2_dbgfs_files[i].fops);
	}

	/* DRM debugfs handles readonly files */
	drm_debugfs_create_files(aie2_debugfs_list, INFO_LIST_ENTRIES,
				 minor->debugfs_root, minor);
}
#else
void aie2_debugfs_init(struct amdxdna_dev *xdna)
{
}
#endif /* CONFIG_DEBUG_FS */
