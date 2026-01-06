// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2022-2025 Advanced Micro Devices, Inc.
 * All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/string.h>
#include <linux/completion.h>
#include <drm/drm_debugfs.h>
#include <drm/drm_cache.h>

#include "aie4_pci.h"
#include "aie4_message.h"
#include "aie4_msg_priv.h"

#if defined(CONFIG_DEBUG_FS)
#define SIZE            31

#define _DBGFS_FOPS_RW(_open, _write) \
{ \
	.owner = THIS_MODULE, \
	.open = _open, \
	.read = seq_read, \
	.llseek = seq_lseek, \
	.release = single_release, \
	.write = _write, \
}

#define DBGFS_FOPS_RW(_name, _show, _write) \
	static int dbgfs_##_name##_open(struct inode *inode, struct file *file) \
	{									\
		return single_open(file, _show, inode->i_private);		\
	}									\
	const struct file_operations fops_##_name =				\
		_DBGFS_FOPS_RW(dbgfs_##_name##_open, _write)

#define DBGFS_FILE(_name, _mode) { #_name, &fops_##_name, _mode }

#define read_file_to_args(file) ((file)->private)

#define write_file_to_args(file) \
	(((struct seq_file *)(file)->private_data)->private)

#define MAKE_MAGIC(a, b, c, d)  ((u32)((a) << 24 | (b) << 16 | (c) << 8 | (d)))

struct debugfs_args {
	struct amdxdna_dev_hdl *ndev;
	int			index;
};

/* test mpaie echo command via mailbox */
static int test_msg_echo_impl(struct amdxdna_dev_hdl *ndev, u32 val1, u32 val2)
{
	DECLARE_AIE4_MSG(aie4_msg_echo, AIE4_MSG_OP_ECHO);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	req.val1 = val1;
	req.val2 = val2;

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);
	if (ret) {
		XDNA_ERR(xdna, "ping fw msg sent failed, ret: %d", ret);
		goto done;
	}

	if (req.val1 == resp.val1 &&
	    req.val2 == resp.val2) {
		XDNA_INFO(xdna, "ping fw succeeded!");
		ret = 0;
	} else {
		XDNA_ERR(xdna, "ping fw echo'ed bad value: 0x%x, 0x%x",
			 resp.val1, resp.val2);
		ret = -EIO;
	}

done:
	XDNA_INFO(xdna, "%s", ret ? ">>TEST FAIL<<" : ">>TEST PASS<<");
	return ret;
}

static int test_msg_echo(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	/* using some random magic number for normal echo test */
	u32 val1 = 0xbaddcafe;
	u32 val2 = 0xdeedbeef;

	XDNA_INFO(xdna, "normal echo: 0x%x 0x%x", val1, val2);
	return test_msg_echo_impl(ndev, val1, val2);
}

static int test_msg_enum(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	/*
	 * Using magic echo to let sideloaded mpnpu enfore some steps which suppose to
	 * be done after pcie device is emulated. Sending this ECHO before run any
	 * tests. This would not affect released version because this step won't not
	 * be run after released.
	 *
	 * Note: only send this special echo once on classic EP setup
	 */
	u32 val1 = MAKE_MAGIC('P', 'C', 'I', 'e');
	u32 val2 = MAKE_MAGIC('M', 'A', 'G', 'C');

	XDNA_INFO(xdna, "special enum echo: 0x%x 0x%x", val1, val2);
	return test_msg_echo_impl(ndev, val1, val2);
}

static int test_flr(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	XDNA_INFO(xdna, "trigger flr");

	mutex_lock(&ndev->aie4_lock);
	aie4_context_quiesce(ndev);
	mutex_unlock(&ndev->aie4_lock);

	ret = pci_save_state(pdev);
	if (ret) {
		XDNA_ERR(xdna, "pci save state failed, ret: %d", ret);
		return ret;
	}

	ret = pcie_reset_flr(pdev, PCI_RESET_DO_RESET);
	if (ret < 0) {
		XDNA_ERR(xdna, "flr failed, ret: %d", ret);
		return ret;
	}
	XDNA_INFO(xdna, "flr performed");

	pci_restore_state(pdev);

	XDNA_INFO(xdna, "pci restore state done");

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_context_restart(ndev);
	mutex_unlock(&ndev->aie4_lock);

	return ret;
}

static int test_msg_identify(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_identify, AIE4_MSG_OP_IDENTIFY);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);
	if (ret) {
		XDNA_ERR(xdna, "identify fw msg sent failed, ret: %d", ret);
		goto done;
	}

	XDNA_INFO(xdna, "firmware major:minor %d.%d",
		  resp.fw_major,
		  resp.fw_minor);
	XDNA_INFO(xdna, "firmware patch:build %d.%d",
		  resp.fw_patch,
		  resp.fw_build);

done:
	XDNA_INFO(xdna, "%s", ret ? ">>TEST FAIL<<" : ">>TEST PASS<<");
	return ret;
}

/* test mpaie tile_info command via mailbox */
static int test_msg_tile_info(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_aie4_tile_info, AIE4_MSG_OP_AIE_TILE_INFO);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);
	if (ret) {
		XDNA_ERR(xdna, "tile info msg sent failed, ret: %d", ret);
		//goto done;
	}

	XDNA_INFO(xdna, "tile info size:columns:rows %d.%d.%d",
		  resp.info.size,
		  resp.info.cols,
		  resp.info.rows);
	XDNA_INFO(xdna, "tile info major:minor %d.%d",
		  resp.info.major,
		  resp.info.minor);
	XDNA_INFO(xdna, "tile info core_rows:mem_rows:shim_rows %d.%d.%d",
		  resp.info.core_rows,
		  resp.info.mem_rows,
		  resp.info.shim_rows);
	XDNA_INFO(xdna, "tile info core_row_start:mem_row_start:shim_row_start %d.%d.%d",
		  resp.info.core_row_start,
		  resp.info.mem_row_start,
		  resp.info.shim_row_start);
	XDNA_INFO(xdna, "tile info core_dma_channels:mem_dma_channels:shim_dma_channels %d.%d.%d",
		  resp.info.core_dma_channels,
		  resp.info.mem_dma_channels,
		  resp.info.shim_dma_channels);
	XDNA_INFO(xdna, "tile info core_locks:mem_locks:shim_locks %d.%d.%d",
		  resp.info.core_locks,
		  resp.info.mem_locks,
		  resp.info.shim_locks);
	XDNA_INFO(xdna, "tile info core_events:mem_events:shim_events %d.%d.%d",
		  resp.info.core_events,
		  resp.info.mem_events,
		  resp.info.shim_events);

//done:
	XDNA_INFO(xdna, "%s", ret ? ">>TEST FAIL<<" : ">>TEST PASS<<");
	return ret;
}

/* test mpaie version_info command via mailbox */
static int test_msg_version_info(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_aie4_version_info, AIE4_MSG_OP_AIE_VERSION_INFO);
	struct amdxdna_dev *xdna = ndev->xdna;
	int ret;

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);
	if (ret) {
		XDNA_ERR(xdna, "version info msg sent failed, ret: %d", ret);
		//goto done;
	}

	XDNA_INFO(xdna, "version info major:minor %d.%d",
		  resp.major,
		  resp.minor);

//done:
	XDNA_INFO(xdna, "%s", ret ? ">>TEST FAIL<<" : ">>TEST PASS<<");
	return ret;
}

/* test mpaie column_info command via mailbox */
static int test_msg_column_info(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_aie4_column_info, AIE4_MSG_OP_AIE_COLUMN_INFO);
	struct amdxdna_dev *xdna = ndev->xdna;
	dma_addr_t dma_addr;
	u8 *buff_addr;
	u32 size = 4096;
	int ret;

	buff_addr = dma_alloc_noncoherent(xdna->ddev.dev, size, &dma_addr,
					  DMA_FROM_DEVICE, GFP_KERNEL);
	if (!buff_addr)
		return -ENOMEM;

	req.dump_buff_addr = dma_addr;
	req.dump_buff_size = size;
	req.num_cols = hweight32(0);
	req.aie4_bitmap = (u32)0;

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);
	if (ret) {
		XDNA_ERR(xdna, "column info msg sent failed, ret: %d", ret);
		//goto done;
	}

	XDNA_INFO(xdna, "size %d",
		  resp.size);

//done:
	dma_free_noncoherent(xdna->ddev.dev, size, buff_addr, dma_addr, DMA_FROM_DEVICE);

	XDNA_INFO(xdna, "%s", ret ? ">>TEST FAIL<<" : ">>TEST PASS<<");
	return ret;
}

static int aie4_telemetry(struct seq_file *m, u32 type)
{
	struct amdxdna_dev_hdl *ndev = m->private;
	struct amdxdna_dev *xdna = ndev->xdna;
	const size_t size = 0x1000;
	dma_addr_t dma_addr;
	void *buff;
	int ret;

	buff = dma_alloc_noncoherent(xdna->ddev.dev, size, &dma_addr,
				     DMA_FROM_DEVICE, GFP_KERNEL);
	if (!buff)
		return -ENOMEM;

	drm_clflush_virt_range(buff, size); /* device can access */
	mutex_lock(&ndev->aie4_lock);
	ret = aie4_query_aie_telemetry(ndev, type, dma_addr, size);
	mutex_unlock(&ndev->aie4_lock);
	if (ret) {
		XDNA_ERR(xdna, "Get telemetry failed ret %d", ret);
		goto free_buf;
	}

	seq_write(m, buff, size);

free_buf:
	dma_free_noncoherent(xdna->ddev.dev, size, buff, dma_addr, DMA_FROM_DEVICE);
	return 0;
}

static int aie4_telemetry_disabled_show(struct seq_file *m, void *unused)
{
	return aie4_telemetry(m, AIE4_TELEMETRY_TYPE_DISABLED);
}

DBGFS_FOPS_RW(telemetry_disabled, aie4_telemetry_disabled_show, NULL);

static int aie4_telemetry_perf_show(struct seq_file *m, void *unused)
{
	return aie4_telemetry(m, AIE4_TELEMETRY_TYPE_PERF_COUNTER);
}

DBGFS_FOPS_RW(telemetry_perf, aie4_telemetry_perf_show, NULL);

/* test mpaie async_event command via mailbox */
static int test_msg_async_event(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_async_event_config, AIE4_MSG_OP_ASYNC_EVENT_MSG);
	struct amdxdna_dev *xdna = ndev->xdna;
	u32 async_buf_size = 8192;
	int ret;

	req.buff_addr = (u64)&async_buf_size;
	req.buff_size = async_buf_size;

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);
	if (ret) {
		XDNA_ERR(xdna, "async event msg sent failed, ret: %d", ret);
		//goto done;
	}

	XDNA_INFO(xdna, "async event type %d",
		  resp.type);
	XDNA_INFO(xdna, "message status %x",
		  resp.status);

//done:
	XDNA_INFO(xdna, "%s", ret ? ">>TEST FAIL<<" : ">>TEST PASS<<");
	return ret;
}

struct test_case {
	char	*test_name;
	int	(*test_func)(struct amdxdna_dev_hdl *ndev);
};

static const struct test_case test_case_array[] = {
	{"echo msg between host and lx7 firmware", test_msg_echo},
	{"firmware identify", test_msg_identify},
	{"aie tile info", test_msg_tile_info},
	{"aie column info", test_msg_column_info},
	{"aie version info", test_msg_version_info},
	{"async event msg", test_msg_async_event},
	{"echo re-enumlate special msg to lx7 firmware", test_msg_enum},
	{"trigger FLR", test_flr},
};

static ssize_t aie4_test_write(struct file *file, const char __user *ptr,
			       size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = write_file_to_args(file);
	int ret, err;
	char input[SIZE + 1];
	unsigned long input_val;

	if (len > SIZE) {
		XDNA_ERR(ndev->xdna, "Length:%ld of the buffer exceeds size:%d", len, SIZE);
		return -EINVAL;
	}

	ret = copy_from_user(input, ptr, len);
	if (ret < 0) {
		XDNA_ERR(ndev->xdna, "Unable to copy from user.");
		return -EINVAL;
	}

	input[len] = '\0';
	err = kstrtoul(input, 10, &input_val);
	if (err) {
		XDNA_ERR(ndev->xdna, "Invalid parameter: %s", input);
		return err;
	}

	if (input_val < ARRAY_SIZE(test_case_array)) {
		XDNA_INFO(ndev->xdna, "test id:%ld name:\"%s\"",
			  input_val, test_case_array[input_val].test_name);
		ret = test_case_array[input_val].test_func(ndev);
	} else {
		XDNA_INFO(ndev->xdna, "test all tests for request:%ld", input_val);
		for (int i = 0; i < ARRAY_SIZE(test_case_array); i++) {
			XDNA_INFO(ndev->xdna, "test id:%d name:\"%s\"",
				  i, test_case_array[i].test_name);
			ret = test_case_array[i].test_func(ndev);
			if (ret)
				break;
		}
	}

	return ret == 0 ? len : ret;
}

static int aie4_test_show(struct seq_file *m, void *unused)
{
	for (int i = 0; i < ARRAY_SIZE(test_case_array); i++)
		seq_printf(m, "test id:%d name:\"%s\"\n",
			   i, test_case_array[i].test_name);

	return 0;
}

DBGFS_FOPS_RW(aie4_test, aie4_test_show, aie4_test_write);

/* 0xFFFF is not a valid pid */
static u32 current_pid = -1U;
/* default is 1 if not specified */
static u32 current_ctx_id = 1;
static u32 current_meta_bo = AMDXDNA_BO_INVALID;

static int cert_pid_show(struct seq_file *m, void *unused)
{
	seq_printf(m, "current pid %d\n", current_pid);
	return 0;
}

static ssize_t cert_pid_write(struct file *file, const char __user *ptr,
			      size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = write_file_to_args(file);
	int ret, err;
	char input[SIZE + 1];
	unsigned long input_val;

	if (len > SIZE) {
		XDNA_ERR(ndev->xdna, "Length:%ld of the buffer exceeds size:%d", len, SIZE);
		return -EINVAL;
	}

	ret = copy_from_user(input, ptr, len);
	if (ret < 0) {
		XDNA_ERR(ndev->xdna, "Unable to copy from user.");
		return -EINVAL;
	}

	input[len] = '\0';
	err = kstrtoul(input, 10, &input_val);
	if (err) {
		XDNA_ERR(ndev->xdna, "Invalid parameter: %s", input);
		return err;
	}

	current_pid = input_val;

	return len;
}

DBGFS_FOPS_RW(cert_pid, cert_pid_show, cert_pid_write);

static int cert_ctx_id_show(struct seq_file *m, void *unused)
{
	seq_printf(m, "current ctx id %d\n", current_ctx_id);
	return 0;
}

static ssize_t cert_ctx_id_write(struct file *file, const char __user *ptr,
				 size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = write_file_to_args(file);
	int ret, err;
	char input[SIZE + 1];
	unsigned long input_val;

	if (len > SIZE) {
		XDNA_ERR(ndev->xdna, "Length:%ld of the buffer exceeds size:%d", len, SIZE);
		return -EINVAL;
	}

	ret = copy_from_user(input, ptr, len);
	if (ret < 0) {
		XDNA_ERR(ndev->xdna, "Unable to copy from user.");
		return -EINVAL;
	}

	input[len] = '\0';
	err = kstrtoul(input, 10, &input_val);
	if (err) {
		XDNA_ERR(ndev->xdna, "Invalid parameter: %s", input);
		return err;
	}

	current_ctx_id = input_val;

	return len;
}

DBGFS_FOPS_RW(cert_ctx_id, cert_ctx_id_show, cert_ctx_id_write);

static int cert_meta_bo_show(struct seq_file *m, void *unused)
{
	seq_printf(m, "current meta bo %d\n", current_meta_bo);
	return 0;
}

static ssize_t cert_meta_bo_write(struct file *file, const char __user *ptr,
				  size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = write_file_to_args(file);
	int ret, err;
	char input[SIZE + 1];
	unsigned long input_val;

	if (len > SIZE) {
		XDNA_ERR(ndev->xdna, "Length:%ld of the buffer exceeds size:%d", len, SIZE);
		return -EINVAL;
	}

	ret = copy_from_user(input, ptr, len);
	if (ret < 0) {
		XDNA_ERR(ndev->xdna, "Unable to copy from user.");
		return -EINVAL;
	}

	input[len] = '\0';
	err = kstrtoul(input, 10, &input_val);
	if (err) {
		XDNA_ERR(ndev->xdna, "Invalid parameter: %s", input);
		return err;
	}

	current_meta_bo = input_val;

	return len;
}

DBGFS_FOPS_RW(cert_meta_bo, cert_meta_bo_show, cert_meta_bo_write);

static void aie4_cert_log_dump(struct seq_file *m, struct amdxdna_client *client, u32 bo_hdl,
			       int index)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_gem_obj *meta_bo;
	struct amdxdna_gem_obj *log_bo;
	struct fw_buffer_metadata *meta_buffer;
	u32 prev_size;

	meta_bo = amdxdna_gem_get_obj(client, bo_hdl, AMDXDNA_BO_SHARE);
	if (!meta_bo) {
		XDNA_ERR(xdna, "Get bo %d failed", bo_hdl);
		return;
	}
	meta_buffer = (struct fw_buffer_metadata *)meta_bo->mem.kva;
	log_bo = amdxdna_gem_get_obj(client, meta_buffer->bo_handle, AMDXDNA_BO_SHARE);
	if (!log_bo) {
		XDNA_ERR(xdna, "Get log_bo %lld failed", meta_buffer->bo_handle);
		goto put_meta_bo;
	}

	prev_size = 0;
	for (int i = 0; i < meta_buffer->num_ucs; i++) {
		struct uc_info_entry *entry = &meta_buffer->uc_info[i];
		u64 off_addr;

		if (entry->index == index) {
			off_addr += prev_size;
			XDNA_INFO(xdna, "dump data for index %d, size %d", index, entry->size);
			seq_write(m, (char *)log_bo->mem.kva + off_addr, entry->size);
			goto put_log_bo;
		}

		if (entry->size == 0)
			continue;
		prev_size += entry->size;
	}

	XDNA_ERR(xdna, "Cannot find data for index %d", index);

put_log_bo:
	amdxdna_gem_put_obj(log_bo);
put_meta_bo:
	amdxdna_gem_put_obj(meta_bo);
}

static int cert_log_show(struct seq_file *m, void *unused)
{
	struct debugfs_args *args = read_file_to_args(m);
	struct amdxdna_dev_hdl *ndev = args->ndev;
	struct amdxdna_dev *xdna = ndev->xdna;
	struct amdxdna_client *client;
	struct amdxdna_ctx *ctx;
	unsigned long ctx_id;

	XDNA_DBG(xdna, "in");

	/*
	 * If current_meta_bo is valid, then honer the meta_bo;
	 * otherwise, each current_pid and current_ctx_id for a match.
	 */
	list_for_each_entry(client, &xdna->client_list, node) {
		amdxdna_for_each_ctx(client, ctx_id, ctx) {
			if (current_meta_bo != AMDXDNA_BO_INVALID) {
				if (ctx->priv->meta_bo_hdl != current_meta_bo)
					continue;

				aie4_cert_log_dump(m, client, ctx->priv->meta_bo_hdl, args->index);
				return 0;
			}

			if (client->pid != current_pid)
				continue;

			if (ctx_id != current_ctx_id)
				continue;

			aie4_cert_log_dump(m, client, ctx->priv->meta_bo_hdl, args->index);
		}
	}

	return 0;
}

DBGFS_FOPS_RW(cert_log, cert_log_show, NULL);

static int aie4_ioctl_id_show(struct seq_file *m, void *unused)
{
#define drm_ioctl_id_seq_print(_name) \
seq_printf(m, "%ld:%s\n", _name, #_name)

	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_CREATE_HWCTX);
	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_DESTROY_HWCTX);
	drm_ioctl_id_seq_print(DRM_IOCTL_AMDXDNA_CONFIG_HWCTX);
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

DBGFS_FOPS_RW(ioctl_id, aie4_ioctl_id_show, NULL);

static ssize_t aie4_dump_fw_log_set(struct file *file, const char __user *ptr,
				    size_t len, loff_t *off)
{
	struct amdxdna_dev_hdl *ndev = write_file_to_args(file);
	struct amdxdna_dev *xdna = ndev->xdna;
	bool dump;
	int ret;

	if (!xdna->fw_log || !xdna->fw_log->enabled) {
		XDNA_ERR(xdna, "FW logging is not enabled");
		return -EINVAL;
	}

	ret =  kstrtobool_from_user(ptr, len, &dump);
	if (ret) {
		XDNA_ERR(xdna, "Invalid input value, ret %d", ret);
		return ret;
	}

	ret = amdxdna_dpt_dump_to_dmesg(xdna->fw_log, dump);
	if (ret) {
		XDNA_ERR(xdna, "Failed to %s FW log dump, ret %d",
			 dump ? "enable" : "disable", ret);
		return ret;
	}
	return len;
}

static int aie4_dump_fw_log_get(struct seq_file *m, void *unused)
{
	struct amdxdna_dev_hdl *ndev = m->private;

	if (!ndev->xdna->fw_log || !ndev->xdna->fw_log->enabled) {
		XDNA_ERR(ndev->xdna, "FW logging is not enabled");
		return -EINVAL;
	}

	seq_printf(m, "%s\n", ndev->xdna->fw_log->dump_to_dmesg ? "enabled" : "disabled");

	return 0;
}

DBGFS_FOPS_RW(dump_fw_log, aie4_dump_fw_log_get, aie4_dump_fw_log_set);

static int aie4_dump_fw_log_buffer_get(struct seq_file *m, void *unused)
{
	struct amdxdna_dev_hdl *ndev = m->private;
	struct amdxdna_mgmt_dma_hdl *dma_hdl;

	if (!ndev->xdna->fw_log || !ndev->xdna->fw_log->enabled) {
		XDNA_ERR(ndev->xdna, "FW logging is not enabled");
		return -EINVAL;
	}

	dma_hdl = ndev->xdna->fw_log->dma_hdl;
	amdxdna_mgmt_buff_clflush(dma_hdl, 0, 0);
	seq_printf(m, "FW log buffer vaddr: 0x%llx\n",
		   (u64)amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0));
	seq_printf(m, "FW log buffer DMA addr: 0x%llx\n", amdxdna_mgmt_buff_get_dma_addr(dma_hdl));
	seq_printf(m, "FW log buffer size: 0x%lx\n", dma_hdl->size);
	seq_hex_dump(m, "[FW LOG BUF]: ", DUMP_PREFIX_OFFSET, 16, 4,
		     amdxdna_mgmt_buff_get_cpu_addr(dma_hdl, 0), dma_hdl->size, true);

	return 0;
}

DBGFS_FOPS_RW(dump_fw_log_buffer, aie4_dump_fw_log_buffer_get, NULL);

static ssize_t aie4_keep_partition_write(struct file *file, const char __user *ptr,
					 size_t len, loff_t *off)
{
	DECLARE_AIE4_MSG(aie4_msg_set_runtime_cfg, AIE4_MSG_OP_SET_RUNTIME_CONFIG);
	struct amdxdna_dev_hdl *ndev = write_file_to_args(file);
	struct amdxdna_dev *xdna = ndev->xdna;
	struct aie4_msg_runtime_config_keep_partitions *keep_partition;
	bool enabled;
	int ret;

	ret = kstrtobool_from_user(ptr, len, &enabled);
	if (ret) {
		XDNA_ERR(ndev->xdna, "Invalid input value, ret %d", ret);
		return ret;
	}

	keep_partition = (struct aie4_msg_runtime_config_keep_partitions *)&req.data;
	keep_partition->enabled = enabled ? 1 : 0;

	req.type = AIE4_RUNTIME_CONFIG_KEEP_PARTITIONS;

	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);

	XDNA_INFO(xdna, "request: %d, %s",
		  *((u32 *)&req.data), ret ? ">>TEST FAIL<<" : ">>TEST PASS<<");

	return ret;
}

DBGFS_FOPS_RW(keep_partition, NULL, aie4_keep_partition_write);

const struct {
	const char *name;
	const struct file_operations *fops;
	umode_t mode;
} dbgfs_files[] = {
	DBGFS_FILE(aie4_test, 0400),
	DBGFS_FILE(cert_log, 0400),
	DBGFS_FILE(cert_pid, 0400),
	DBGFS_FILE(cert_ctx_id, 0400),
	DBGFS_FILE(cert_meta_bo, 0400),
	DBGFS_FILE(telemetry_disabled, 0400),
	DBGFS_FILE(telemetry_perf, 0400),
	DBGFS_FILE(ioctl_id, 0400),
	DBGFS_FILE(dump_fw_log, 0600),
	DBGFS_FILE(dump_fw_log_buffer, 0400),
	DBGFS_FILE(keep_partition, 0600),
};

void aie4_debugfs_init(struct amdxdna_dev *xdna)
{
	struct drm_minor *minor = xdna->ddev.accel;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct dentry *debugfs_subdir;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);

	for (int i = 0; i < ARRAY_SIZE(dbgfs_files); i++) {
		/* skip creating cert_log in parent dir */
		if (i == 1)
			continue;

		debugfs_create_file(dbgfs_files[i].name,
				    dbgfs_files[i].mode,
				    minor->debugfs_root,
				    ndev,
				    dbgfs_files[i].fops);
	}

	ndev->dbgfs_args =
		devm_kzalloc(&pdev->dev, sizeof(struct debugfs_args) * MAX_NUM_CERTS, GFP_KERNEL);

	for (int i = 0; i < MAX_NUM_CERTS; i++) {
		char sub_dir[32] = "";

		snprintf(sub_dir, sizeof(sub_dir), "cert_index_%d", i);

		debugfs_subdir = debugfs_create_dir(sub_dir, minor->debugfs_root);
		if (!debugfs_subdir || IS_ERR(debugfs_subdir)) {
			XDNA_ERR(xdna, "failed to create debugfs %s", sub_dir);
			return;
		}

		ndev->dbgfs_args[i].ndev = ndev;
		ndev->dbgfs_args[i].index = i;

		/* only create cert_log in child dir */
		debugfs_create_file(dbgfs_files[1].name,
				    dbgfs_files[1].mode,
				    debugfs_subdir,
				    &ndev->dbgfs_args[i],
				    dbgfs_files[1].fops);
	}

	XDNA_DBG(xdna, "debugfs init finished");
}

#else
void aie4_debugfs_init(struct amdxdna_dev *xdna)
{
}
#endif /* CONFIG_DEBUG_FS */
