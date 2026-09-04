// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * Transport-independent aie4 core: query/policy helpers.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_cache.h>
#include <drm/drm_drv.h>
#include <linux/pm_runtime.h>
#include <linux/rcupdate.h>

#include "aie.h"
#include "aie4.h"
#include "aie4_msg_priv.h"
#include "amdxdna_coredump.h"
#include "amdxdna_ctx.h"
#include "amdxdna_ctx_status.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_dpt.h"
#include "amdxdna_error.h"
#include "amdxdna_gem.h"
#include "amdxdna_mailbox_helper.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_pm.h"
#include "amdxdna_sensors.h"
#include "amdxdna_tile_read_write.h"

#define AIE4_TOTAL_COLUMN	3

int aie4_partition_init(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE_MSG(aie4_msg_create_partition, AIE4_MSG_OP_CREATE_PARTITION);
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret;

	req.partition_col_start = 0;
	req.partition_col_count = AIE4_TOTAL_COLUMN;
	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret) {
		XDNA_ERR(xdna, "partition init failed: %d", ret);
		return ret;
	}

	ndev->partition_id = resp.partition_id;
	return 0;
}

void aie4_partition_fini(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE_MSG(aie4_msg_destroy_partition, AIE4_MSG_OP_DESTROY_PARTITION);
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret;

	req.partition_id = ndev->partition_id;
	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(xdna, "partition fini failed: %d", ret);
}

/*
 * Firmware always boots in POWER_MODE_DEFAULT after a (re)load, so re-send the
 * cached user override whenever the hardware starts. This keeps the driver
 * cache (ndev->pw_mode) and the firmware power state consistent across
 * suspend/resume and runtime PM cycles. On a fresh probe pw_mode is
 * POWER_MODE_DEFAULT and this is a no-op. The override is a best-effort tuning
 * knob, so a failure warns but does not fail hw start (mirrors ctx hysteresis).
 *
 * Power override is a per-VF property in firmware: each supervisor (VF) stores
 * its own requested mode and the hypervisor arbitrates globally by taking the
 * highest mode across all supervisors. A full firmware reload on suspend clears
 * every supervisor override back to default, so each device type (PF, VF and
 * classic) must re-send its own cached override on resume.
 */
void aie4_restore_power_mode(struct amdxdna_dev_hdl *ndev)
{
	if (ndev->pw_mode == POWER_MODE_DEFAULT)
		return;

	aie4_msg_set_power_mode(ndev, ndev->pw_mode);
}

/*
 * A full firmware reload on suspend puts the scheduler back to its default of
 * no forced preemption, so a cached enable has to be re-sent on resume. Only an
 * enable is worth sending, disabled being that default. Force preemption is a
 * debug and test knob, so a failure warns rather than failing hw start.
 */
void aie4_restore_force_preemption(struct amdxdna_dev_hdl *ndev)
{
	if (!ndev->aie.force_preempt_enabled)
		return;

	aie4_force_preemption(ndev, true);
}

int aie4_query_fw(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	int ret;

	ret = aie4_query_npu_firmware_version(ndev, &xdna->fw_ver);
	if (ret)
		return ret;

	ret = aie4_query_cert_firmware_version(ndev, &ndev->cert_version);
	if (ret)
		return ret;

	aie4_restore_power_mode(ndev);
	aie4_restore_force_preemption(ndev);

	return 0;
}

int aie4_setup_aie(struct amdxdna_dev_hdl *ndev)
{
	int ret;

	ret = aie4_query_aie_version(ndev, &ndev->aie.version);
	if (ret)
		return ret;

	ret = aie4_query_aie_metadata(ndev, &ndev->aie.metadata);
	if (ret)
		return ret;

	/*
	 * Do not reset ndev->pw_mode here: this runs on every resume, and
	 * clobbering the cache would drop the user's power override. The
	 * probe-time default is set in aie4m_pcidev_init(), and the cached
	 * override is re-applied to firmware by aie4_restore_power_mode().
	 */
	ndev->total_col = min(AIE4_TOTAL_COLUMN, ndev->aie.metadata.cols);
	ndev->aie.frame_boundary_preempt_enabled = 1;

	ret = aie4_init_dpm_freq_table(ndev);
	if (ret)
		/* if query dpm from fw failed, using default value */
		(void)aie4_set_dpm(ndev, 0);

	ret = aie4_partition_init(ndev);
	if (ret)
		return ret;

	ret = amdxdna_async_events_alloc(&ndev->aie, ndev->total_col);
	if (ret) {
		XDNA_ERR(ndev->aie.xdna, "Allocate async events failed, ret %d", ret);
		goto partition_fini;
	}

	return 0;

partition_fini:
	aie4_partition_fini(ndev);
	return ret;
}

static int aie4_get_power_mode(struct amdxdna_client *client,
			       struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_get_power_mode mode = {};
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int min;

	ndev = xdna->dev_handle;
	mode.power_mode = ndev->pw_mode;

	min = min(args->buffer_size, sizeof(mode));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &mode, min))
		return -EFAULT;

	return 0;
}

static int aie4_query_clock_metadata(struct amdxdna_client *client,
				     struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_query_clock_metadata *clock;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev;
	int ret = 0;
	u32 buf_sz;

	ndev = xdna->dev_handle;
	clock = kzalloc_obj(*clock);
	if (!clock)
		return -ENOMEM;

	aie4_update_counters(ndev);
	snprintf(clock->mp_npu_clock.name, sizeof(clock->mp_npu_clock.name),
		 "NPU H Clock");
	clock->mp_npu_clock.freq_mhz = ndev->aie.npuclk_freq;
	snprintf(clock->h_clock.name, sizeof(clock->h_clock.name), "AIE Clock");
	clock->h_clock.freq_mhz = ndev->aie.hclk_freq;

	buf_sz = min(args->buffer_size, sizeof(*clock));
	if (copy_to_user(u64_to_user_ptr(args->buffer), clock, buf_sz))
		ret = -EFAULT;

	kfree(clock);
	return ret;
}

static int aie4_query_resource_info(struct amdxdna_client *client,
				    struct amdxdna_drm_get_info *args)
{
	struct amdxdna_drm_get_resource_info res_info = {};
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;
	u32 buf_sz;

	xdna = client->xdna;
	ndev = xdna->dev_handle;

	aie4_update_counters(ndev);
	res_info.npu_clk_max = ndev->dpm_clk_tbl[ndev->max_dpm_level].hclk;
	res_info.npu_tops_max = ndev->aie.max_tops;
	res_info.npu_tops_curr = ndev->aie.curr_tops;

	buf_sz = min(args->buffer_size, sizeof(res_info));
	if (copy_to_user(u64_to_user_ptr(args->buffer), &res_info, buf_sz))
		return -EFAULT;

	return 0;
}

int aie4_get_info(struct amdxdna_client *client, struct amdxdna_drm_get_info *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto dev_exit;

	switch (args->param) {
	case DRM_AMDXDNA_QUERY_AIE_STATUS:
		ret = amdxdna_get_aie_status(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_METADATA:
		ret = amdxdna_get_metadata(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_QUERY_AIE_VERSION:
		ret = amdxdna_get_aie_version(client, args, &ndev->aie.version);
		break;
	case DRM_AMDXDNA_QUERY_CLOCK_METADATA:
		ret = aie4_query_clock_metadata(client, args);
		break;
	case DRM_AMDXDNA_QUERY_SENSORS:
		ret = amdxdna_query_sensors(args, AIE4_TOTAL_COLUMN);
		break;
	case DRM_AMDXDNA_QUERY_FIRMWARE_VERSION:
		ret = amdxdna_get_firmware_version(client, args, &xdna->fw_ver);
		break;
	case DRM_AMDXDNA_QUERY_CERT_FIRMWARE_VERSION:
		ret = amdxdna_get_firmware_version(client, args, &ndev->cert_version);
		break;
	case DRM_AMDXDNA_GET_POWER_MODE:
		ret = aie4_get_power_mode(client, args);
		break;
	case DRM_AMDXDNA_QUERY_RESOURCE_INFO:
		ret = aie4_query_resource_info(client, args);
		break;
	case DRM_AMDXDNA_QUERY_HW_CONTEXTS:
		ret = amdxdna_get_hwctx_status(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_QUERY_TELEMETRY:
		ret = amdxdna_get_telemetry(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_GET_FORCE_PREEMPT_STATE:
		ret = amdxdna_get_force_preempt_state(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_GET_FRAME_BOUNDARY_PREEMPT_STATE:
		ret = amdxdna_get_frame_boundary_preempt_state(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_GET_AUTO_COREDUMP:
		ret = amdxdna_get_auto_coredump_mode(client, args);
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
	}

	amdxdna_pm_suspend_put(xdna);
	XDNA_DBG(xdna, "Got param %d", args->param);

dev_exit:
	drm_dev_exit(idx);
	return ret;
}

/*
 * Hand firmware a defined work buffer instead of relying on it to clear its own
 * partitions. Four of the five partition init callbacks memset on attach, but
 * the telemetry one only records the pointer, so its counters would otherwise
 * start from whatever the page allocator left behind.
 */
void aie4_zero_work_buffer(struct amdxdna_dev_hdl *ndev)
{
	void *vaddr;
	u32 size;

	if (!ndev->work_buf_hdl)
		return;

	vaddr = to_cpu_addr(ndev->work_buf_hdl, 0);
	size = to_buf_size(ndev->work_buf_hdl);
	memset(vaddr, 0, size);
	drm_clflush_virt_range(vaddr, size);
}

int aie4_alloc_work_buffer(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;

	ndev->work_buf_hdl = amdxdna_alloc_msg_buff(xdna, AIE4_WORK_BUFFER_MIN_SIZE);
	if (IS_ERR(ndev->work_buf_hdl)) {
		int ret = PTR_ERR(ndev->work_buf_hdl);

		XDNA_ERR(xdna, "Failed to alloc work buffer, size 0x%x",
			 AIE4_WORK_BUFFER_MIN_SIZE);
		ndev->work_buf_hdl = NULL;
		return ret;
	}

	/* amdxdna_alloc_msg_buff() does not zero, and firmware attaches this. */
	aie4_zero_work_buffer(ndev);

	XDNA_DBG(xdna, "Work buffer allocated: size 0x%x",
		 to_buf_size(ndev->work_buf_hdl));

	return 0;
}

void aie4_free_work_buffer(struct amdxdna_dev_hdl *ndev)
{
	if (!ndev->work_buf_hdl)
		return;

	amdxdna_free_msg_buff(ndev->work_buf_hdl);
	ndev->work_buf_hdl = NULL;
}

int aie4_get_array(struct amdxdna_client *client,
		   struct amdxdna_drm_get_array *args)
{
	struct amdxdna_dev_hdl *ndev = client->xdna->dev_handle;
	struct amdxdna_dev *xdna = client->xdna;
	bool needs_dev_lock;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	/* FW_LOG / FW_TRACE paths use SRCU instead of dev_lock so multiple
	 * xrt-smi watchers can sleep in wait_event_interruptible concurrently
	 * while an admin can still disable logging / tracing via the
	 * corresponding SET state ioctl.
	 */
	switch (args->param) {
	case DRM_AMDXDNA_FW_LOG:
	case DRM_AMDXDNA_FW_LOG_CONFIG:
	case DRM_AMDXDNA_FW_TRACE:
	case DRM_AMDXDNA_FW_TRACE_CONFIG:
		needs_dev_lock = false;
		break;
	default:
		needs_dev_lock = true;
		break;
	}

	ret = amdxdna_pm_resume_get(xdna);
	if (ret)
		goto dev_exit;

	if (needs_dev_lock)
		mutex_lock(&xdna->dev_lock);

	switch (args->param) {
	case DRM_AMDXDNA_HW_CONTEXT_ALL:
		ret = amdxdna_query_ctx_status_array(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_HW_CONTEXT_BY_ID:
		ret = amdxdna_query_ctx_status_by_id(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_AIE_COREDUMP:
		ret = amdxdna_get_coredump(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_AIE_TILE_READ:
		ret = amdxdna_aie_tile_read(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_HW_LAST_ASYNC_ERR:
		ret = aie4_get_array_async_error(ndev, args);
		break;
	case DRM_AMDXDNA_BO_USAGE:
		ret = amdxdna_drm_get_bo_usage(&xdna->ddev, args);
		break;
	case DRM_AMDXDNA_FW_LOG:
		ret = amdxdna_get_fw_log(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_FW_LOG_CONFIG:
		ret = amdxdna_get_fw_log_configs(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_FW_TRACE:
		ret = amdxdna_get_fw_trace(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_FW_TRACE_CONFIG:
		ret = amdxdna_get_fw_trace_configs(&ndev->aie, args);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	if (needs_dev_lock)
		mutex_unlock(&xdna->dev_lock);

	amdxdna_pm_suspend_put(xdna);

dev_exit:
	drm_dev_exit(idx);
	return ret;
}

/*
 * Power override is a per-VF request but a single physical outcome. Firmware
 * keeps a separate override per supervisor (one supervisor per VF mailbox under
 * SR-IOV) and arbitrates them globally with a highest-wins policy: the applied
 * DPM level is derived from max(override) across all supervisors, ordered
 * DEFAULT < LOW < MEDIUM < HIGH < TURBO. Consequences when VFs disagree:
 *
 *   - The device runs at the highest mode any VF has requested. Example: VF A
 *     requests TURBO and VF B requests LOW, the whole device runs at TURBO.
 *   - A VF cannot pull the device below a peer's request. Lowering (or
 *     resetting to DEFAULT) one VF only drops the physical DPM level once no
 *     other VF still holds a higher override.
 *   - Every VF's request is honored; there is no PF-only restriction on this
 *     opcode (unlike force preemption, which firmware rejects under SR-IOV).
 *
 * The driver therefore just records this VF's own request in ndev->pw_mode and
 * forwards it; the cross-VF arbitration lives entirely in firmware.
 */
static int aie4_set_power_mode(struct amdxdna_client *client, struct amdxdna_drm_set_state *args)
{
	struct amdxdna_drm_set_power_mode power_state;
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	int ret;
	u8 power_mode;

	if (copy_from_user(&power_state, u64_to_user_ptr(args->buffer),
			   sizeof(power_state))) {
		XDNA_ERR(xdna, "Failed to copy power mode request into kernel");
		return -EFAULT;
	}

	if (XDNA_MBZ_DBG(xdna, power_state.pad, sizeof(power_state.pad)))
		return -EINVAL;

	power_mode = power_state.power_mode;
	if (power_mode > POWER_MODE_TURBO) {
		XDNA_ERR(xdna, "Invalid power mode %d", power_mode);
		return -EINVAL;
	}

	ret = aie4_msg_set_power_mode(xdna->dev_handle, power_mode);
	if (ret)
		return ret;

	ndev->pw_mode = power_mode;
	return 0;
}

void aie4_hwctx_suspend_all(struct amdxdna_dev_hdl *ndev, int clean_jobs)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	struct amdxdna_client *client;
	struct amdxdna_hwctx *hwctx;
	unsigned long hwctx_id;
	int idx;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	amdxdna_for_each_client(xdna, client) {
		idx = srcu_read_lock(&client->hwctx_srcu);
		amdxdna_for_each_hwctx(client, hwctx_id, hwctx) {
			/* clean up workers and drain running jobs */
			if (clean_jobs) {
				aie4_hwctx_destroy(hwctx, AIE4_HWCTX_ERROR);
				aie4_hwctx_wait_for_running(hwctx);
			} else {
				aie4_hwctx_destroy(hwctx, AIE4_HWCTX_NORMAL);
			}
		}
		srcu_read_unlock(&client->hwctx_srcu, idx);
	}

	XDNA_DBG(xdna, "Finished hwctx suspend");
}

int aie4_hwctx_resume_all(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	struct amdxdna_client *client;
	struct amdxdna_hwctx *hwctx;
	unsigned long hwctx_id;
	int ret, idx;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	amdxdna_for_each_client(xdna, client) {
		idx = srcu_read_lock(&client->hwctx_srcu);
		amdxdna_for_each_hwctx(client, hwctx_id, hwctx) {
			ret = aie4_hwctx_create(hwctx);
			if (ret)
				goto error;
			aie4_hwctx_resume_jobs(hwctx);
		}
		srcu_read_unlock(&client->hwctx_srcu, idx);
	}

	XDNA_DBG(xdna, "Finished hwctx resume");
	return 0;
error:
	srcu_read_unlock(&client->hwctx_srcu, idx);
	XDNA_DBG(xdna, "Failed hwctx resume");
	return ret;
}

void aie4_hwctx_disconnect_all(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	struct amdxdna_client *client;
	struct amdxdna_hwctx *hwctx;
	unsigned long hwctx_id;
	int idx;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	amdxdna_for_each_client(xdna, client) {
		idx = srcu_read_lock(&client->hwctx_srcu);
		amdxdna_for_each_hwctx(client, hwctx_id, hwctx) {
			/* AIE4_HWCTX_DISCONNECT will not talk to firmware */
			aie4_hwctx_destroy(hwctx, AIE4_HWCTX_DISCONNECT);
		}
		srcu_read_unlock(&client->hwctx_srcu, idx);
	}
}

int aie4_hwctx_reconnect_all(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	struct amdxdna_client *client;
	struct amdxdna_hwctx *hwctx;
	unsigned long hwctx_id;
	int ret, idx;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	amdxdna_for_each_client(xdna, client) {
		idx = srcu_read_lock(&client->hwctx_srcu);
		amdxdna_for_each_hwctx(client, hwctx_id, hwctx) {
			/* when reset is done, safely abort all previously running jobs. */
			aie4_hwctx_wait_for_running(hwctx);
			XDNA_INFO(xdna, "aborting hwctx_id %lu", hwctx_id);

			/* firmware is stateless, thus no need to send destroy request. */
			ret = aie4_hwctx_create(hwctx);
			if (ret) {
				srcu_read_unlock(&client->hwctx_srcu, idx);
				return ret;
			}

			aie4_hwctx_resume_jobs(hwctx);
			XDNA_INFO(xdna, "resumed hwctx_id %u", hwctx->priv->hw_ctx_id);
		}
		srcu_read_unlock(&client->hwctx_srcu, idx);
	}

	return 0;
}

/*
 * Force preemption is one global flag in the firmware scheduler, not a
 * per-context or per-client one, and it stays set until firmware is told
 * otherwise. Send both edges down as they are asked for: firmware samples the
 * flag when it loads a context, so a stale enable preempts every later context,
 * whoever created it. aie2 names the context in its own runtime config and so
 * arms per context instead, which is why this cannot be shared with it.
 */
static int aie4_set_force_preempt_state(struct amdxdna_client *client,
					struct amdxdna_drm_set_state *args)
{
	struct amdxdna_dev_hdl *ndev = client->xdna->dev_handle;
	struct amdxdna_drm_attribute_state state = {};
	u32 buf_sz;
	int ret;

	buf_sz = min(args->buffer_size, sizeof(state));
	if (copy_from_user(&state, u64_to_user_ptr(args->buffer), buf_sz))
		return -EFAULT;

	if (state.state > 1)
		return -EINVAL;

	if (XDNA_MBZ_DBG(client->xdna, state.pad, sizeof(state.pad)))
		return -EINVAL;

	ret = aie4_force_preemption(ndev, state.state);
	if (ret)
		return ret;

	ndev->aie.force_preempt_enabled = state.state;

	return 0;
}

int aie4_set_state(struct amdxdna_client *client,
		   struct amdxdna_drm_set_state *args, u32 *settle_ms)
{
	struct amdxdna_dev_hdl *ndev = client->xdna->dev_handle;
	struct amdxdna_dev *xdna = client->xdna;
	int ret, idx;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return -ENODEV;

	ret = amdxdna_pm_resume_get_locked(xdna);
	if (ret)
		goto dev_exit;

	switch (args->param) {
	case DRM_AMDXDNA_SET_POWER_MODE:
		ret = aie4_set_power_mode(client, args);
		break;
	case DRM_AMDXDNA_SET_FORCE_PREEMPT:
		ret = aie4_set_force_preempt_state(client, args);
		break;
	case DRM_AMDXDNA_AIE_TILE_WRITE:
		ret = amdxdna_aie_tile_write(&ndev->aie, client, args);
		break;
	case DRM_AMDXDNA_SET_FW_LOG_STATE:
		ret = amdxdna_set_fw_log_state(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_SET_FW_TRACE_STATE:
		ret = amdxdna_set_fw_trace_state(&ndev->aie, args);
		break;
	case DRM_AMDXDNA_SET_AUTO_COREDUMP:
		/* TODO: enable debug mode on FW if auto coredump is enabled,
		 * then call amdxdna_set_auto_coredump_mode(client, args).
		 */
		ret = -EOPNOTSUPP;
		break;
	default:
		XDNA_ERR(xdna, "Not supported request parameter %u", args->param);
		ret = -EOPNOTSUPP;
		break;
	}

	amdxdna_pm_suspend_put(xdna);

dev_exit:
	drm_dev_exit(idx);
	return ret;
}
