// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <drm/drm_drv.h>
#include <linux/debugfs.h>
#include <linux/limits.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>

#include "aie.h"
#include "aie4.h"
#include "amdxdna_drv.h"
#include "amdxdna_pm.h"

static int aie4_ctx_hysteresis_get(void *data, u64 *val)
{
	struct amdxdna_dev_hdl *ndev = data;
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	u32 timeout_us;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	mutex_lock(&xdna->dev_lock);

	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto unlock;

	/*
	 * Report firmware's value but do not cache it: the cache holds what hw
	 * start and resume re-apply, which may differ from firmware's default
	 * if that best-effort SET failed.
	 */
	ret = aie4_get_ctx_hysteresis(ndev, &timeout_us);
	if (!ret)
		*val = timeout_us;

	amdxdna_pm_suspend_put(xdna);

unlock:
	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);

	return ret;
}

static int aie4_ctx_hysteresis_set(void *data, u64 val)
{
	struct amdxdna_dev_hdl *ndev = data;
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret, idx;

	if (val > U32_MAX)
		return -EINVAL;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	mutex_lock(&xdna->dev_lock);

	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto unlock;

	ret = aie4_set_ctx_hysteresis(ndev, (u32)val);
	if (!ret)
		ndev->ctx_switch_hysteresis_us = (u32)val;

	amdxdna_pm_suspend_put(xdna);

unlock:
	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);

	return ret;
}

/* Context switch hysteresis timeout in microseconds; 0 disables hysteresis. */
DEFINE_DEBUGFS_ATTRIBUTE(aie4_ctx_hysteresis_fops, aie4_ctx_hysteresis_get,
			 aie4_ctx_hysteresis_set, "%llu\n");

static int aie4_cert_timeout_get(void *data, u64 *val)
{
	struct amdxdna_dev_hdl *ndev = data;

	*val = ndev->cert_timeout_ms;
	return 0;
}

static int aie4_cert_timeout_set(void *data, u64 val)
{
	struct amdxdna_dev_hdl *ndev = data;
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret, idx;

	if (val > U32_MAX)
		return -EINVAL;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	mutex_lock(&xdna->dev_lock);

	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto unlock;

	ret = aie4_set_cert_timeout(ndev, (u32)val);
	if (!ret)
		ndev->cert_timeout_ms = (u32)val;

	amdxdna_pm_suspend_put(xdna);

unlock:
	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);

	return ret;
}

/* CERT opcode deadlock interval in milliseconds. 0 disables the checker. */
DEFINE_DEBUGFS_ATTRIBUTE(aie4_cert_timeout_fops, aie4_cert_timeout_get,
			 aie4_cert_timeout_set, "%llu\n");

static int aie4_kernel_submit_get(void *data, u64 *val)
{
	struct amdxdna_dev_hdl *ndev = data;

	*val = ndev->kernel_submit;
	return 0;
}

/* Read-only: a NULL set returns -EACCES on write, even for root. */
DEFINE_DEBUGFS_ATTRIBUTE(aie4_kernel_submit_fops, aie4_kernel_submit_get,
			 NULL, "%llu\n");

static int aie4_npufw_time_get(void *data, u64 *val)
{
	struct amdxdna_dev_hdl *ndev = data;
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	u64 timestamp_ns = 0;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	mutex_lock(&xdna->dev_lock);

	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto unlock;

	ret = aie4_get_npufw_time(ndev, &timestamp_ns);

	amdxdna_pm_suspend_put(xdna);

unlock:
	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);

	if (!ret)
		*val = timestamp_ns;

	return ret;
}

/* Current NPU firmware timestamp in nanoseconds (read-only). */
DEFINE_DEBUGFS_ATTRIBUTE(aie4_npufw_time_fops, aie4_npufw_time_get,
			 NULL, "%llu\n");

/*
 * DPM activity monitor parameters currently in effect in firmware (read-only).
 * Firmware reports resolved values, so a field programmed as 0 (keep default)
 * reads back as the firmware default. The compute and BW configs are
 * independent, so leave out a config this device does not support, but fail
 * the read if any supported config could not be read.
 */
static int aie4_dpm_config_show(struct seq_file *m, void *unused)
{
	struct aie4_msg_runtime_config_configure_dpm_bw bw = {};
	struct aie4_msg_runtime_config_configure_dpm dpm = {};
	struct amdxdna_dev_hdl *ndev = m->private;
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret, ret_dpm = -EOPNOTSUPP, ret_bw = -EOPNOTSUPP;
	int idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	mutex_lock(&xdna->dev_lock);

	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto unlock;

	if (AIE_FEATURE_ON(&ndev->aie, AIE4_CONFIGURE_DPM))
		ret_dpm = aie4_get_dpm_compute_params(ndev, &dpm);
	if (AIE_FEATURE_ON(&ndev->aie, AIE4_DPM_BW_BUSYNESS))
		ret_bw = aie4_get_dpm_bw_params(ndev, &bw);

	amdxdna_pm_suspend_put(xdna);

	if (ret_dpm && ret_dpm != -EOPNOTSUPP)
		ret = ret_dpm;
	else if (ret_bw && ret_bw != -EOPNOTSUPP)
		ret = ret_bw;
	else if (ret_dpm && ret_bw)
		ret = -EOPNOTSUPP;

unlock:
	mutex_unlock(&xdna->dev_lock);
	drm_dev_exit(idx);

	if (ret)
		return ret;

	if (!ret_dpm) {
		seq_printf(m, "active_hysteresis_ms: %u\n", dpm.active_hysteresis_ms);
		seq_printf(m, "sampling_window_ms: %u\n", dpm.sampling_window_ms);
		seq_printf(m, "up_threshold: %u\n", dpm.up_threshold);
		seq_printf(m, "down_threshold: %u\n", dpm.down_threshold);
		seq_printf(m, "compute_sys_efficiency_percent: %u\n",
			   dpm.compute_sys_efficiency_percent);
		seq_printf(m, "bw_sys_efficiency_percent: %u\n",
			   dpm.bw_sys_efficiency_percent);
	}
	if (!ret_bw) {
		seq_printf(m, "bw_high_cac_threshold: %u\n", bw.bw_high_cac_threshold);
		seq_printf(m, "bw_low_cac_threshold: %u\n", bw.bw_low_cac_threshold);
		seq_printf(m, "bw_sampling_window_ms: %u\n", bw.bw_sampling_window_ms);
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(aie4_dpm_config);

/*
 * kernel_mode_submission: 0 - submit by user space, 1 - submit by driver.
 * Transports without a user-mappable doorbell support only kernel-mode
 * submission and expose it read-only (a NULL debugfs set, so writes fail with
 * -EACCES even for root).
 */
void aie4_debugfs_add_kernel_submit(struct amdxdna_dev *xdna, bool writable)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	if (writable)
		debugfs_create_bool("kernel_mode_submission", 0600,
				    xdna->ddev.accel->debugfs_root,
				    &ndev->kernel_submit);
	else
		debugfs_create_file_unsafe("kernel_mode_submission", 0400,
					   xdna->ddev.accel->debugfs_root, ndev,
					   &aie4_kernel_submit_fops);
}

void aie4_debugfs_add_ctx_hysteresis(struct amdxdna_dev *xdna)
{
	debugfs_create_file_unsafe("ctx_switch_hysteresis_us", 0600,
				   xdna->ddev.accel->debugfs_root, xdna->dev_handle,
				   &aie4_ctx_hysteresis_fops);
}

/*
 * A read returns the value cached at setup. A write sends runtime-config 0x6
 * and returns the firmware error when the device does not implement it.
 * 0 disables the checker.
 */
void aie4_debugfs_add_cert_timeout(struct amdxdna_dev *xdna)
{
	debugfs_create_file_unsafe("cert_timeout_ms", 0600,
				   xdna->ddev.accel->debugfs_root, xdna->dev_handle,
				   &aie4_cert_timeout_fops);
}

void aie4_debugfs_add_dpm_config(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	if (!AIE_FEATURE_ON(&ndev->aie, AIE4_CONFIGURE_DPM) &&
	    !AIE_FEATURE_ON(&ndev->aie, AIE4_DPM_BW_BUSYNESS))
		return;

	debugfs_create_file("dpm_config", 0400,
			    xdna->ddev.accel->debugfs_root, ndev,
			    &aie4_dpm_config_fops);
}

void aie4_debugfs_init(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	/*
	 * NPU firmware timestamp is fetched over the firmware mailbox, which
	 * every aie4 transport brings up, so expose it wherever the firmware
	 * supports it.
	 */
	if (AIE_FEATURE_ON(&ndev->aie, AIE4_GET_NPUFW_TIME))
		debugfs_create_file_unsafe("npu_fw_time", 0400,
					   xdna->ddev.accel->debugfs_root, ndev,
					   &aie4_npufw_time_fops);

	aie4_transport_debugfs_init(xdna);
}
