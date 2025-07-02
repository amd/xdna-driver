// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2025, Advanced Micro Devices, Inc.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/completion.h>
#include <linux/pm_runtime.h>
#include <drm/drm_debugfs.h>
#include <drm/drm_cache.h>

#include "aie2_msg_priv.h"
#include "aie2_pci.h"

#if defined(CONFIG_DEBUG_FS)
#define LOG_LEVEL_BUF_SIZE	11
#define MIN_INPUT_ARG_SIZE	8
#define MAX_INPUT_ARG_SIZE	40
#define SIZE			31

#define TX_TIMEOUT 2000 /* milliseconds */
#define RX_TIMEOUT 5000 /* milliseconds */

static int aie2_dbgfs_entry_open(struct inode *inode, struct file *file,
				 int (*show)(struct seq_file *, void *))
{
	struct amdxdna_dev_hdl *ndev = inode->i_private;
	int ret;

	ret = pm_runtime_resume_and_get(ndev->xdna->ddev.dev);
	if (ret)
		return ret;

	ret = single_open(file, show, ndev);
	if (ret) {
		pm_runtime_mark_last_busy(ndev->xdna->ddev.dev);
		pm_runtime_put_autosuspend(ndev->xdna->ddev.dev);
	}

	return ret;
}

static int aie2_dbgfs_entry_release(struct inode *inode, struct file *file)
{
	struct amdxdna_dev_hdl *ndev = inode->i_private;

	pm_runtime_mark_last_busy(ndev->xdna->ddev.dev);
	pm_runtime_put_autosuspend(ndev->xdna->ddev.dev);
	return single_release(inode, file);
}

#define _DBGFS_FOPS(_open, _release, _write) \
{ \
	.owner = THIS_MODULE, \
	.open = _open, \
	.read = seq_read, \
	.llseek = seq_lseek, \
	.release = _release, \
	.write = _write, \
}

#define AIE2_DBGFS_FOPS(_name, _show, _write) \
	static int aie2_dbgfs_##_name##_open(struct inode *inode, struct file *file) \
	{ \
		return aie2_dbgfs_entry_open(inode, file, _show); \
	} \
	static int aie2_dbgfs_##_name##_release(struct inode *inode, struct file *file) \
	{ \
		return aie2_dbgfs_entry_release(inode, file); \
	} \
	static const struct file_operations aie2_fops_##_name = \
		_DBGFS_FOPS(aie2_dbgfs_##_name##_open, aie2_dbgfs_##_name##_release, _write)

#define AIE2_DBGFS_FILE(_name, _mode) { #_name, &aie2_fops_##_name, _mode }

#define file_to_ndev_rw(file) \
	(((struct seq_file *)(file)->private_data)->private)

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
	struct amdxdna_dev_hdl *ndev = m->private;
	int ret;

	ret = aie2_smu_get_power_state(ndev);
	if (ret < 0)
		return ret;

	switch (ret) {
	case SMU_POWER_ON:
		seq_puts(m, "SMU power ON\n");
		break;
	case SMU_POWER_OFF:
		seq_puts(m, "SMU power OFF\n");
		break;
	default:
		seq_puts(m, "SMU power ??? (buggy)\n");
	}

	return 0;
}

AIE2_DBGFS_FOPS(powerstate, aie2_power_state_show, aie2_power_state_write);

static ssize_t aie2_dpm_level_set(struct file *file, const char __user *ptr,
				  size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = file_to_ndev_rw(file);
	u32 val;
	int ret;

	ret = kstrtoint_from_user(ptr, len, 10, &val);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Invalid input value: %d", val);
		return ret;
	}

	mutex_lock(&ndev->aie2_lock);
	ndev->dft_dpm_level = val;
	if (ndev->pw_mode != POWER_MODE_DEFAULT)
		val = ndev->dpm_level;
	ret = ndev->priv->hw_ops.set_dpm(ndev, val);
	mutex_unlock(&ndev->aie2_lock);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Setting dpm_level:%d failed, ret: %d", val, ret);
		return ret;
	}
	return len;
}

static int aie2_dpm_level_get(struct seq_file *m, void *unused)
{
	struct amdxdna_dev_hdl *ndev = m->private;
	const struct dpm_clk_freq *dpm_table;
	int dpm_level;
	int i;

	dpm_table = ndev->priv->dpm_clk_tbl;
	dpm_level = ndev->dpm_level;
	for (i = 0; dpm_table[i].hclk; i++) {
		u32 npuclk = dpm_table[i].npuclk;
		u32 hclk = dpm_table[i].hclk;

		if (dpm_level == i)
			seq_printf(m, " [%d,%d] ", npuclk, hclk);
		else
			seq_printf(m, " %d,%d ", npuclk, hclk);
	}
	seq_puts(m, "\n");
	return 0;
}

AIE2_DBGFS_FOPS(dpm_level, aie2_dpm_level_get, aie2_dpm_level_set);

static const char *aie2_event_trace_input_info(void)
{
	return	"echo enable=1 size=1K category=0xFFFFFF -> Follow given input format to enable\n"
		"enable=[0, 1] -> enable=1 to enable, enable=0 to disable\n"
		"size=[1K, 2K, 4K...512K to 1M] -> buffer size should be pow of 2\n"
		"category=[0x1 - 0xFFFFFFFF] -> 32 bit word\n";
}

static ssize_t aie2_event_trace_write(struct file *file, const char __user *buf,
				      size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = file_to_ndev_rw(file);
	char event_trace_cfg_buf[MAX_INPUT_ARG_SIZE + 1];
	u32 enable = 0, buf_size = 0, event_category = 0;
	char *kbuf, *token, *key, *val;
	int ret = 0;

	if (len < MIN_INPUT_ARG_SIZE || len > MAX_INPUT_ARG_SIZE) {
		XDNA_ERR(ndev->xdna, "Input length %zu beyond buffer size [%d, %d]",
			 len, MIN_INPUT_ARG_SIZE, MAX_INPUT_ARG_SIZE);
		return -EINVAL;
	}

	kbuf = event_trace_cfg_buf;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;

	kbuf[len] = '\0';
	token = strsep(&kbuf, " ");

	while (token) {
		key = strsep(&token, "=");
		val = token;

		if (key && val) {
			if (strcmp(key, "enable") == 0) {
				ret = kstrtouint(val, 10, &enable);
				if (ret) {
					ret = -EINVAL;
					goto out;
				}
			} else if (strcmp(key, "size") == 0) {
				buf_size = memparse(val, NULL);
			} else if (strcmp(key, "category") == 0) {
				ret = kstrtouint(val, 0, &event_category);
				if (ret) {
					ret = -EINVAL;
					goto out;
				}
			} else {
				ret = -EINVAL;
				goto out;
			}
		}
		token = strsep(&kbuf, " ");
	}

	if (enable && (!buf_size || !event_category)) {
		XDNA_ERR(ndev->xdna, "Invalid config: %u, %u, 0x%08x",
			 enable, buf_size, event_category);
		ret = -EINVAL;
		goto out;
	}

	aie2_config_event_trace(ndev, enable, buf_size, event_category);
	return len;

out:
	if (ret == -EINVAL)
		XDNA_INFO(ndev->xdna, "%s", aie2_event_trace_input_info());

	return ret;
}

static int aie2_event_trace_show(struct seq_file *m, void *unused)
{
	struct amdxdna_dev_hdl *ndev = m->private;

	if (aie2_is_event_trace_enable(ndev))
		seq_puts(m, "Event trace is enabled\n");
	else
		seq_printf(m, "Event trace is disabled\n%s",
			   aie2_event_trace_input_info());
	return 0;
}

AIE2_DBGFS_FOPS(event_trace, aie2_event_trace_show, aie2_event_trace_write);

static const char *aie2_dram_logging_input_info(void)
{
	return	"echo enable=1 size=1K loglevel=4 -> Follow given input format to enable\n"
		"enable=[0, 1] -> enable=1 to enable, enable=0 to disable\n"
		"size=[1K, 2K, 4K...512K to 1M] -> buffer size should be pow of 2\n"
		"loglevel=[0 - 4] -> None-Err...Dbg\n";
}

static ssize_t aie2_dram_logging_write(struct file *file, const char __user *buf,
				       size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = file_to_ndev_rw(file);
	u32 enable = 0, buf_size = 0, loglevel = 0;
	char *kbuf, *token, *key, *val;
	int ret = 0;

	if (len < MIN_INPUT_ARG_SIZE || len > MAX_INPUT_ARG_SIZE) {
		XDNA_ERR(ndev->xdna, "Input length %zu beyond buffer size [%d, %d]",
			 len, MIN_INPUT_ARG_SIZE, MAX_INPUT_ARG_SIZE);
		return -EINVAL;
	}

	kbuf = kzalloc(len + 1, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, buf, len)) {
		ret = -EFAULT;
		goto out;
	}

	kbuf[len] = '\0';
	token = strsep(&kbuf, " ");

	while (token) {
		key = strsep(&token, "=");
		val = token;

		if (key && val) {
			if (strcmp(key, "enable") == 0) {
				ret = kstrtouint(val, 10, &enable);
				if (ret) {
					ret = -EINVAL;
					goto out;
				}
			} else if (strcmp(key, "size") == 0) {
				buf_size = memparse(val, NULL);
			} else if (strcmp(key, "loglevel") == 0) {
				ret = kstrtouint(val, 0, &loglevel);
				if (ret) {
					ret = -EINVAL;
					goto out;
				}
			} else {
				ret = -EINVAL;
				goto out;
			}
		}
		token = strsep(&kbuf, " ");
	}

	if (enable && !buf_size) {
		XDNA_ERR(ndev->xdna, "Invalid config: %u, %u, %u",
			 enable, buf_size, loglevel);
		ret = -EINVAL;
		goto out;
	}

	aie2_set_dram_log_config(ndev, enable, buf_size, loglevel);
	ret = len;

out:
	if (ret == -EINVAL)
		XDNA_INFO(ndev->xdna, "%s", aie2_dram_logging_input_info());

	kfree(kbuf);
	return ret;
}

static int aie2_dram_logging_show(struct seq_file *m, void *unused)
{
	struct amdxdna_dev_hdl *ndev = m->private;

	if (aie2_is_dram_logging_enable(ndev))
		seq_puts(m, "Dram logging is enabled\n");
	else
		seq_printf(m, "Dram logging is disabled\n%s",
			   aie2_dram_logging_input_info());
	return 0;
}

AIE2_DBGFS_FOPS(dram_logging, aie2_dram_logging_show, aie2_dram_logging_write);

static ssize_t aie2_log_runtime_cfg_write(struct file *file, const char __user *buf,
					  size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = file_to_ndev_rw(file);
	char log_level_buf[LOG_LEVEL_BUF_SIZE + 1];
	char *kbuf, *token, *key, *val;
	u32 loglevel;
	int ret;

	if (len > LOG_LEVEL_BUF_SIZE) {
		XDNA_ERR(ndev->xdna, "Input length %zu > buffer size %d",
			 len, LOG_LEVEL_BUF_SIZE);
		return -EINVAL;
	}

	kbuf = log_level_buf;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;

	kbuf[len] = '\0';
	token = strsep(&kbuf, " ");

	if (token) {
		key = strsep(&token, "=");
		val = token;

		if (!key || !val) {
			XDNA_ERR(ndev->xdna, "Invalid \'key=val\' pair e.g loglevel=[0-4]");
			return -EINVAL;
		}

		if (strcmp(key, "loglevel") == 0) {
			ret = kstrtouint(val, 0, &loglevel);
			if (ret || loglevel > 4) {
				XDNA_ERR(ndev->xdna, "Invalid log level %u",
					 loglevel);
				return -EINVAL;
			}

			ret = aie2_set_log_level(ndev, loglevel);
			if (ret) {
				XDNA_ERR(ndev->xdna, "Failed to set log level: %d", ret);
				return ret;
			}
		} else {
			XDNA_ERR(ndev->xdna, "Invalid key %s, e.g. loglevel=[0-4]", key);
			return -EINVAL;
		}
	}

	return len;
}

static int aie2_log_runtime_cfg_show(struct seq_file *m, void *unused)
{
	struct amdxdna_dev_hdl *ndev = m->private;
	u32 log_level;

	if (!aie2_is_dram_logging_enable(ndev)) {
		seq_puts(m, "Dram logging is disabled\n");
	} else {
		log_level = aie2_get_log_level(ndev);
		seq_printf(m, "log level %u\n", log_level);
		seq_puts(m, "To change log level echo loglevel=[0-4]\n");
	}

	return 0;
}

AIE2_DBGFS_FOPS(log_runtime_cfg, aie2_log_runtime_cfg_show, aie2_log_runtime_cfg_write);

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

static int test_case02_cb(void *handle, void __iomem *data, size_t size)
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

	mutex_lock(&ndev->aie2_lock);
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
	mutex_unlock(&ndev->aie2_lock);

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

static int aie2_ringbuf_show(struct seq_file *m, void *unused)
{
	struct amdxdna_dev_hdl *ndev = m->private;

	return xdna_mailbox_ringbuf_show(ndev->mbox, m);
}

AIE2_DBGFS_FOPS(ringbuf, aie2_ringbuf_show, NULL);

static int aie2_ioctl_id_show(struct seq_file *m, void *unused)
{
#define drm_ioctl_id_seq_print(_name) \
seq_printf(m, "%ld:%s\n", _name, #_name)

	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_CREATE_CTX);
	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_DESTROY_CTX);
	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_CONFIG_CTX);
	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_CREATE_BO);
	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_GET_BO_INFO);
	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_SYNC_BO);
	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_EXEC_CMD);
	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_WAIT_CMD);
	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_GET_INFO);
	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_SET_STATE);

	drm_ioctl_id_seq_print(DRM_IOCTL_GEM_CLOSE);
	drm_ioctl_id_seq_print(DRM_IOCTL_PRIME_HANDLE_TO_FD);
	drm_ioctl_id_seq_print(DRM_IOCTL_PRIME_FD_TO_HANDLE);
	drm_ioctl_id_seq_print(DRM_IOCTL_SYNCOBJ_CREATE);
	drm_ioctl_id_seq_print(DRM_IOCTL_SYNCOBJ_DESTROY);
	drm_ioctl_id_seq_print(DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE);
	drm_ioctl_id_seq_print(DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD);
	drm_ioctl_id_seq_print(DRM_IOCTL_SYNCOBJ_QUERY);
	drm_ioctl_id_seq_print(DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL);
	drm_ioctl_id_seq_print(DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT);
	return 0;
}

AIE2_DBGFS_FOPS(ioctl_id, aie2_ioctl_id_show, NULL);

static int aie2_msg_queue_show(struct seq_file *m, void *unused)
{
	struct amdxdna_dev_hdl *ndev = m->private;

	return xdna_mailbox_info_show(ndev->mbox, m);
}

AIE2_DBGFS_FOPS(msg_queue, aie2_msg_queue_show, NULL);

static int aie2_telemetry(struct seq_file *m, u32 type)
{
	struct amdxdna_dev_hdl *ndev = m->private;
	struct amdxdna_dev *xdna = ndev->xdna;
	struct aie2_mgmt_dma_hdl mgmt_hdl;
	const size_t size = 0x1000;
	void *buff;
	int ret;

	buff = aie2_mgmt_buff_alloc(ndev, &mgmt_hdl, size, DMA_FROM_DEVICE);
	if (!buff)
		return -ENOMEM;

	aie2_mgmt_buff_clflush(&mgmt_hdl);
	mutex_lock(&ndev->aie2_lock);
	ret = aie2_query_aie_telemetry(ndev, &mgmt_hdl, type, size, NULL);
	mutex_unlock(&ndev->aie2_lock);
	if (ret) {
		XDNA_ERR(xdna, "Get telemetry failed ret %d", ret);
		goto free_buf;
	}

	seq_write(m, buff, size);

free_buf:
	aie2_mgmt_buff_free(&mgmt_hdl);
	return 0;
}

static int aie2_telemetry_disabled_show(struct seq_file *m, void *unused)
{
	return aie2_telemetry(m, TELEMETRY_TYPE_DISABLED);
}

AIE2_DBGFS_FOPS(telemetry_disabled, aie2_telemetry_disabled_show, NULL);

static int aie2_telemetry_health_show(struct seq_file *m, void *unused)
{
	return aie2_telemetry(m, TELEMETRY_TYPE_HEALTH);
}

AIE2_DBGFS_FOPS(telemetry_health, aie2_telemetry_health_show, NULL);

static int aie2_telemetry_error_info_show(struct seq_file *m, void *unused)
{
	return aie2_telemetry(m, TELEMETRY_TYPE_ERROR_INFO);
}

AIE2_DBGFS_FOPS(telemetry_error_info, aie2_telemetry_error_info_show, NULL);

static int aie2_telemetry_profiling_show(struct seq_file *m, void *unused)
{
	return aie2_telemetry(m, TELEMETRY_TYPE_PROFILING);
}

AIE2_DBGFS_FOPS(telemetry_profiling, aie2_telemetry_profiling_show, NULL);

static int aie2_telemetry_debug_show(struct seq_file *m, void *unused)
{
	return aie2_telemetry(m, TELEMETRY_TYPE_DEBUG);
}

AIE2_DBGFS_FOPS(telemetry_debug, aie2_telemetry_debug_show, NULL);

static int aie2_ctx_rq_show(struct seq_file *m, void *unused)
{
	struct amdxdna_dev_hdl *ndev = m->private;

	return aie2_rq_show(&ndev->ctx_rq, m);
}

AIE2_DBGFS_FOPS(ctx_rq, aie2_ctx_rq_show, NULL);

static int aie2_get_app_health_show(struct seq_file *m, void *unused)
{
	struct amdxdna_dev_hdl *ndev = m->private;
	struct amdxdna_dev *xdna = ndev->xdna;
	struct aie2_mgmt_dma_hdl mgmt_hdl;
	struct app_health_report *report;
	const size_t size = 0x2000;
	void *buff;
	int ret;

	buff = aie2_mgmt_buff_alloc(ndev, &mgmt_hdl, size, DMA_FROM_DEVICE);
	if (!buff)
		return -ENOMEM;

	aie2_mgmt_buff_clflush(&mgmt_hdl);
	mutex_lock(&ndev->aie2_lock);
	/* Just for debug, always check context id 1 */
	ret = aie2_get_app_health(ndev, &mgmt_hdl, 1, size);
	mutex_unlock(&ndev->aie2_lock);
	if (ret) {
		XDNA_ERR(xdna, "Get app health failed ret %d", ret);
		goto free_buf;
	}

	report = buff;
	seq_printf(m, "version    %d.%d\n", report->major, report->minor);
	seq_printf(m, "size       %d\n", report->size);
	seq_printf(m, "context_id %d\n", report->context_id);
	seq_printf(m, "dpu_pc     0x%x\n", report->dpu_pc);
	seq_printf(m, "txn_op_id  0x%x\n", report->txn_op_id);

free_buf:
	aie2_mgmt_buff_free(&mgmt_hdl);
	return 0;
}

AIE2_DBGFS_FOPS(get_app_health, aie2_get_app_health_show, NULL);

const struct {
	const char *name;
	const struct file_operations *fops;
	umode_t mode;
} aie2_dbgfs_files[] = {
	AIE2_DBGFS_FILE(nputest, 0600),
	AIE2_DBGFS_FILE(pasid, 0600),
	AIE2_DBGFS_FILE(powerstate, 0600),
	AIE2_DBGFS_FILE(dpm_level, 0600),
	AIE2_DBGFS_FILE(ringbuf, 0400),
	AIE2_DBGFS_FILE(msg_queue, 0400),
	AIE2_DBGFS_FILE(ioctl_id, 0400),
	AIE2_DBGFS_FILE(telemetry_disabled, 0400),
	AIE2_DBGFS_FILE(telemetry_health, 0400),
	AIE2_DBGFS_FILE(telemetry_error_info, 0400),
	AIE2_DBGFS_FILE(telemetry_profiling, 0400),
	AIE2_DBGFS_FILE(telemetry_debug, 0400),
	AIE2_DBGFS_FILE(event_trace, 0600),
	AIE2_DBGFS_FILE(ctx_rq, 0400),
	AIE2_DBGFS_FILE(get_app_health, 0400),
	AIE2_DBGFS_FILE(dram_logging, 0600),
	AIE2_DBGFS_FILE(log_runtime_cfg, 0600),
};

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
}
#else
void aie2_debugfs_init(struct amdxdna_dev *xdna)
{
}
#endif /* CONFIG_DEBUG_FS */
