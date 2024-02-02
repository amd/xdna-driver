// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 *
 * Authors:
 *	Min Ma <min.ma@amd.com>
 */

#include <linux/version.h>
#include <linux/kref.h>
#include <drm/drm_file.h>
#include <drm/drm_cache.h>
#include "drm_local/amdxdna_accel.h"

#include "amdxdna_drv.h"
#include "amdxdna_ctx.h"
#include "amdxdna_xclbin.h"
#include "ipu_pci.h"

#define MAX_HWCTX_ID		255

enum ert_cmd_state {
	ERT_CMD_STATE_INVALID,
	ERT_CMD_STATE_NEW,
	ERT_CMD_STATE_QUEUED,
	ERT_CMD_STATE_RUNNING,
	ERT_CMD_STATE_COMPLETED,
	ERT_CMD_STATE_ERROR,
	ERT_CMD_STATE_ABORT,
	ERT_CMD_STATE_SUBMITTED,
	ERT_CMD_STATE_TIMEOUT,
	ERT_CMD_STATE_NORESPONSE,
};

/* Exec buffer command header format */
struct amdxdna_start_cmd {
	union {
		struct {
			u32 state:4;
			u32 stat_enabled:1;
			u32 unused:5;
			u32 extra_cu_masks:2;
			u32 count:11;
			u32 opcode:5;
			u32 type:4;
		};
		u32 header;
	};
	u32 cu_mask;
	u32 data[];
};

#define drm_job_to_xdna_job(j) \
	container_of(j, struct amdxdna_sched_job, base)

struct amdxdna_sched_job {
	struct drm_sched_job	base;
	struct kref		refcnt;
	struct amdxdna_hwctx	*hwctx;
	/* The fence to notice DRM scheduler that job is done by hardware */
	struct dma_fence	*fence;
	/* user can wait on this fence */
	struct dma_fence	*out_fence;
	u32			cu_idx;
	struct amdxdna_start_cmd *cmd;
	struct amdxdna_gem_obj	*cmd_abo;
	u64			seq;
};

struct amdxdna_fence {
	struct dma_fence	base;
	spinlock_t		lock; /* for base */
};

static const char *amdxdna_fence_get_driver_name(struct dma_fence *fence)
{
	return KBUILD_MODNAME;
}

static const char *amdxdna_fence_get_timeline_name(struct dma_fence *fence)
{
	return "xdna_fence";
}

static void amdxdna_fence_release(struct dma_fence *fence)
{
	kfree(fence);
}

static const struct dma_fence_ops fence_ops = {
	.get_driver_name = amdxdna_fence_get_driver_name,
	.get_timeline_name = amdxdna_fence_get_timeline_name,
	.release = amdxdna_fence_release,
};

static struct dma_fence *amdxdna_fence_create(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_fence *fence;

	fence = kzalloc(sizeof(*fence), GFP_KERNEL);
	if (!fence)
		return NULL;

	spin_lock_init(&fence->lock);
	dma_fence_init(&fence->base, &fence_ops, &fence->lock, hwctx->id, 0);
	return &fence->base;
}

static void amdxdna_sched_job_release(struct kref *ref)
{
	struct amdxdna_sched_job *job;

	job = container_of(ref, struct amdxdna_sched_job, refcnt);

	drm_gem_object_put(&job->cmd_abo->base);
	kfree(job);
}

static void amdxdna_job_put(struct amdxdna_sched_job *job)
{
	kref_put(&job->refcnt, amdxdna_sched_job_release);
}

static int amdxdna_sched_job_init(struct amdxdna_sched_job *job,
				  struct amdxdna_hwctx *hwctx,
				  struct amdxdna_gem_obj *abo)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 *cu_mask;
	int i, ret;

	job->cmd_abo = abo;
	job->cmd = abo->mem.kva;
	if (!job->cmd) {
		XDNA_ERR(xdna, "Cmd KVA not found");
		return -EINVAL;
	}

	job->cmd->state = ERT_CMD_STATE_NEW;
	job->hwctx = hwctx;

	job->fence = amdxdna_fence_create(hwctx);
	if (!job->fence) {
		XDNA_ERR(xdna, "Failed to create fence");
		return -ENOMEM;
	}

	cu_mask = &job->cmd->cu_mask;
	for (i = 0; i < 1 + job->cmd->extra_cu_masks; i++) {
		job->cu_idx = ffs(cu_mask[i]) - 1;

		if (job->cu_idx != -1)
			break;
	}
	if (job->cu_idx == -1) {
		ret = -EINVAL;
		goto fail;
	}

	ret = drm_sched_job_init(&job->base, &hwctx->entity, hwctx);
	if (ret)
		goto fail;

	kref_init(&job->refcnt);
	drm_sched_job_arm(&job->base);

	return 0;

fail:
	dma_fence_put(job->fence);
	return ret;
}

static void amdxdna_sched_job_clean(struct amdxdna_sched_job *job)
{
	drm_sched_job_cleanup(&job->base);
	dma_fence_put(job->fence);
}

static void
amdxdna_sched_resp_handler(void *handle, const u32 *data, size_t size)
{
	struct amdxdna_sched_job *job = handle;
	u32 status;

	if (!data) {
		job->cmd->state = ERT_CMD_STATE_ABORT;
		goto out;
	}

	print_hex_dump_debug("resp data: ", DUMP_PREFIX_OFFSET, 16, 4, data, size, true);

	status = *data;
	if (status)
		job->cmd->state = ERT_CMD_STATE_ERROR;
	else
		job->cmd->state = ERT_CMD_STATE_COMPLETED;

out:
	dma_fence_signal(job->fence);
	dma_fence_put(job->fence);
	amdxdna_job_put(job);
}

static struct dma_fence *
amdxdna_sched_job_run(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_hwctx *hwctx = job->hwctx;
	struct dma_fence *fence;
	struct amdxdna_dev *xdna;
	void *cmd_buf;
	int ret, idx;

	xdna = hwctx->client->xdna;

	if (!drm_dev_enter(&xdna->ddev, &idx))
		return ERR_PTR(-ENODEV);

	kref_get(&job->refcnt);
	fence = dma_fence_get(job->fence);
	cmd_buf = &job->cmd->data[job->cmd->extra_cu_masks];
	ret = ipu_execbuf(xdna->dev_handle, hwctx->mbox_chan, job->cu_idx,
			  cmd_buf, job, amdxdna_sched_resp_handler);
	if (ret) {
		dma_fence_put(job->fence);
		amdxdna_job_put(job);
		fence = ERR_PTR(ret);
	}
	drm_dev_exit(idx);

	return fence;
}

static void amdxdna_sched_job_free(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);

	drm_sched_job_cleanup(sched_job);
	amdxdna_job_put(job);
}

static enum drm_gpu_sched_stat
amdxdna_sched_job_timeout(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_dev *xdna = job->hwctx->client->xdna;

	drm_sched_stop(sched_job->sched, sched_job);

	XDNA_DBG(xdna, "%s cmd %lld timedout", job->hwctx->name, job->seq);
	mutex_lock(&xdna->dev_lock);
	/* Destroy mailbox channel, abort all commands */
	ipu_destroy_context(xdna->dev_handle, job->hwctx);

	/* Re-connect HW context and IPUFW */
	ipu_create_context(xdna->dev_handle, job->hwctx);
	mutex_unlock(&xdna->dev_lock);

	drm_sched_start(sched_job->sched, true);

	return DRM_GPU_SCHED_STAT_NOMINAL;
}

static const struct drm_sched_backend_ops sched_ops = {
	.run_job = amdxdna_sched_job_run,
	.free_job = amdxdna_sched_job_free,
	.timedout_job = amdxdna_sched_job_timeout,
};

static inline u64
amdxdna_hwctx_add_fence(struct amdxdna_hwctx *hwctx, struct dma_fence *fence)
{
	struct dma_fence *other;
	int idx;

	idx = hwctx->seq & (HWCTX_MAX_CMDS - 1);
	/* When pending list full, hwctx->seq points to oldest fence */
	other = hwctx->pending[idx];
	if (other && !dma_fence_is_signaled(other))
		return AMDXDNA_INVALID_CMD_HANDLE;

	if (other)
		dma_fence_put(other);

	hwctx->pending[idx] = fence;

	return hwctx->seq++;
}

static inline struct dma_fence *
amdxdna_hwctx_get_fence(struct amdxdna_hwctx *hwctx, u64 seq)
{
	struct dma_fence *fence;
	int idx;

	/* Special sequence number for oldest fence if exist */
	if (seq == AMDXDNA_INVALID_CMD_HANDLE) {
		idx = hwctx->seq & (HWCTX_MAX_CMDS - 1);
		fence = hwctx->pending[idx];
		if (fence)
			goto get_fence;

		goto out;
	}

	if (seq >= hwctx->seq) {
		fence = ERR_PTR(-EINVAL);
		goto out;
	}

	if (seq + HWCTX_MAX_CMDS < hwctx->seq) {
		fence = NULL;
		goto out;
	}

	idx = seq & (HWCTX_MAX_CMDS - 1);

get_fence:
	fence = dma_fence_get(hwctx->pending[idx]);
out:
	return fence;
}

static void amdxdna_hwctx_cleanup(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	int ret;

	ret = ipu_release_resource(hwctx);
	if (ret)
		XDNA_ERR(xdna, "release hw resource failed, ret %d", ret);

	XDNA_DBG(xdna, "hwctx %s cleanup completed", hwctx->name);
}

static int amdxdna_hwctx_init(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	int ret;

	ret = ipu_alloc_resource(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "alloc hw resource failed, ret %d", ret);
		goto out;
	}

	XDNA_DBG(xdna, "hwctx %s init completed", hwctx->name);

	ret = ipu_config_cu(xdna->dev_handle, hwctx->mbox_chan, hwctx->xclbin);
	if (ret) {
		XDNA_ERR(xdna, "Config CU failed, ret %d", ret);
		goto release_resource;
	}

	return 0;

release_resource:
	ipu_release_resource(hwctx);
out:
	return ret;
}

static void amdxdna_hwctx_release(struct amdxdna_hwctx *hwctx)
{
	struct dma_fence *fence;
	struct amdxdna_dev *xdna;
	int idx;

	xdna = hwctx->client->xdna;
	sysfs_mgr_remove_directory(xdna->sysfs_mgr, &hwctx->dir);
	mutex_lock(&xdna->dev_lock);
	amdxdna_hwctx_cleanup(hwctx);
	amdxdna_xclbin_unload(xdna, hwctx->xclbin);
	mutex_unlock(&xdna->dev_lock);
	drm_sched_entity_destroy(&hwctx->entity);
	drm_sched_fini(&hwctx->sched);

	for (idx = 0; idx < HWCTX_MAX_CMDS; idx++) {
		fence = hwctx->pending[idx];
		if (!fence)
			continue;

		dma_fence_put(fence);
	}
	XDNA_DBG(xdna, "%s sequence number %lld", hwctx->name, hwctx->seq);

	amdxdna_unpin_pages(&hwctx->heap->mem);
	drm_gem_object_put(&hwctx->heap->base);
	kfree(hwctx->name);
	kfree(hwctx);
}

static struct amdxdna_hwctx *
amdxdna_hwctx_find_by_id(struct amdxdna_client *client, u32 hwctx_id)
{
	struct amdxdna_hwctx *hwctx;

	mutex_lock(&client->hwctx_lock);
	hwctx = idr_find(&client->hwctx_idr, hwctx_id);
	mutex_unlock(&client->hwctx_lock);
	return hwctx;
}

/*
 * The IP name and index buffer layout,
 * +----------------------+
 * | IP name offset       |
 * | IP index             |
 * +----------------------+
 * | IP name offset       |
 * | IP index             |
 * +----------------------+
 * | ......               |
 * +----------------------+
 * | 0                    |
 * | 0                    |
 * +----------------------+
 * | IP name string       |
 * +----------------------+
 * | IP name string       |
 * +----------------------+
 * | ......               |
 * +----------------------+
 * The name string is end by '\0'.
 */
static int amdxdna_hwctx_fill_ip_buf(struct amdxdna_xclbin *xclbin,
				     void __user *ip_buf_p, u32 size)
{
	struct amdxdna_ip_name_index *header;
	int i, ret = 0;
	u32 name_off;
	void *buf;

	/* there is an empty entry at the end of ip name array */
	name_off = (xclbin->num_cus + 1) * sizeof(*header);
	if (name_off >= size)
		return -EINVAL;

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	header = (struct amdxdna_ip_name_index *)buf;
	for (i = 0; i < xclbin->num_cus; i++) {
		header[i].name_off = name_off;
		header[i].index = xclbin->cu[i].index;

		name_off += snprintf(buf + name_off, size - name_off, "%s",
				     xclbin->cu[i].name);
		name_off++;
		if (name_off > size) {
			ret = -EAGAIN;
			goto free_and_out;
		}
	}

	if (copy_to_user(ip_buf_p, buf, name_off))
		ret = -EFAULT;

free_and_out:
	kfree(buf);
	return ret;
}

static int
amdxdna_hwctx_create(struct amdxdna_client *client, struct amdxdna_xclbin *xclbin,
		     struct amdxdna_gem_obj *heap, struct amdxdna_qos_info *qos,
		     u32 *hwctx_id)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct drm_gpu_scheduler *sched;
	struct amdxdna_hwctx *hwctx;
	int ret;

	ret = amdxdna_pin_pages(&heap->mem);
	if (ret) {
		XDNA_ERR(xdna, "Dev heap pin failed, ret %d", ret);
		return ret;
	}

	hwctx = kzalloc(sizeof(*hwctx), GFP_KERNEL);
	if (!hwctx) {
		ret = -ENOMEM;
		goto unpin;
	}

	mutex_lock(&client->hwctx_lock);
	ret = idr_alloc_cyclic(&client->hwctx_idr, hwctx, 0, MAX_HWCTX_ID, GFP_KERNEL);
	if (ret < 0) {
		mutex_unlock(&client->hwctx_lock);
		XDNA_ERR(xdna, "Allocate hwctx ID failed, ret %d", ret);
		goto free_hwctx;
	}
	hwctx->id = ret;
	mutex_unlock(&client->hwctx_lock);

	hwctx->client = client;
	hwctx->xclbin = xclbin;
	hwctx->heap = heap;

	hwctx->qos.gops = qos->gops;
	hwctx->qos.fps = qos->fps;
	hwctx->qos.dma_bw = qos->dma_bandwidth;
	hwctx->qos.latency = qos->latency;
	hwctx->qos.exec_time = qos->frame_exec_time;
	hwctx->qos.priority = qos->priority;

	hwctx->name = kasprintf(GFP_KERNEL, "hwctx.%d.%d", client->pid, hwctx->id);
	if (!hwctx->name) {
		ret = -ENOMEM;
		goto rm_id;
	}

	ret = sysfs_mgr_generate_directory(xdna->sysfs_mgr, &client->dir, &hwctx_group,
					   &hwctx->dir, hwctx->name);
	if (ret) {
		XDNA_ERR(xdna, "Create hwctx directory failed, ret %d", ret);
		goto free_name;
	}

	sched = &hwctx->sched;
#if KERNEL_VERSION(6, 7, 0) <= LINUX_VERSION_CODE
	ret = drm_sched_init(sched, &sched_ops, DRM_SCHED_PRIORITY_COUNT, HWCTX_MAX_CMDS,
			     0, MAX_SCHEDULE_TIMEOUT, NULL, NULL,
			     hwctx->name, &client->xdna->pdev->dev);
#else
	ret = drm_sched_init(sched, &sched_ops, HWCTX_MAX_CMDS,
			     0, MAX_SCHEDULE_TIMEOUT, NULL, NULL,
			     hwctx->name, &client->xdna->pdev->dev);
#endif
	if (ret) {
		XDNA_ERR(xdna, "Failed to init DRM scheduler. ret %d", ret);
		goto rm_hwctx_dir;
	}

	ret = drm_sched_entity_init(&hwctx->entity, DRM_SCHED_PRIORITY_NORMAL,
				    &sched, 1, NULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to initial sched entiry. ret %d", ret);
		goto free_sched;
	}

	ret = amdxdna_hwctx_init(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "Create firmware context failed, ret %d", ret);
		goto free_entity;
	}

	ret = ipu_map_host_buf(xdna->dev_handle, hwctx->fw_ctx_id,
			       heap->mem.userptr, heap->mem.size);
	if (ret) {
		XDNA_ERR(xdna, "Map host buffer failed, ret %d", ret);
		goto hwctx_cleanup;
	}

	hwctx->destroyed = false;
	*hwctx_id = hwctx->id;

	return 0;

hwctx_cleanup:
	amdxdna_hwctx_cleanup(hwctx);
free_entity:
	drm_sched_entity_destroy(&hwctx->entity);
free_sched:
	drm_sched_fini(&hwctx->sched);
rm_hwctx_dir:
	sysfs_mgr_remove_directory(xdna->sysfs_mgr, &hwctx->dir);
free_name:
	kfree(hwctx->name);
rm_id:
	idr_remove(&client->hwctx_idr, hwctx->id);
free_hwctx:
	kfree(hwctx);
unpin:
	amdxdna_unpin_pages(&heap->mem);
	return ret;
}

static int amdxdna_hwctx_col_match(struct amdxdna_hwctx *hwctx, u32 col_map)
{
	u32 start_col, end_col;

	start_col = hwctx->start_col;
	end_col = start_col + hwctx->num_col - 1;

	return col_map & GENMASK(end_col, start_col);
}

int amdxdna_hwctx_stop(struct amdxdna_client *client, u32 col_map)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0, ret = 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	/*
	 * Multiple HW context can reference same AIE partition.
	 * To reset AIE partition, it needs to destroy all associated hardware
	 * contexts.
	 *
	 * 1. Find out each HW context that is using the error partition
	 * 2. Stop scheduling in the context
	 * 3. Abort all submitted messages by destroy IPUFW context
	 * 4. Add stopped HW context into a list for later start
	 *
	 * Note, when this function return, it doesn't mean partition is reset.
	 * The caller needs iterate all clients and call into this function
	 * to make sure partition is reset on the hardware.
	 */
	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		if (!amdxdna_hwctx_col_match(hwctx, col_map))
			continue;

		hwctx->stopped = true;

		XDNA_DBG(xdna, "Stop %s", hwctx->name);
		drm_sched_stop(&hwctx->sched, NULL);

		/*
		 * If return error, it must be management issue.
		 * For HW context, it is save to ignore this error.
		 */
		ret = ipu_destroy_context(xdna->dev_handle, hwctx);
		WARN_ONCE(ret, "destroy context failed, ret %d", ret);
	}
	mutex_unlock(&client->hwctx_lock);
	return ret;
}

int amdxdna_hwctx_reset_restart(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0, ret = 0;

	WARN_ON(!mutex_is_locked(&xdna->dev_lock));

	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		if (!hwctx->stopped)
			continue;

		XDNA_DBG(xdna, "Resetting %s", hwctx->name);
		ret = ipu_create_context(xdna->dev_handle, hwctx);
		if (unlikely(ret)) {
			XDNA_ERR(xdna, "Create fwctx failed, ret %d", ret);
			goto err_out;
		}

		ret = ipu_config_cu(xdna->dev_handle, hwctx->mbox_chan, hwctx->xclbin);
		if (unlikely(ret)) {
			XDNA_ERR(xdna, "Config cu failed, ret %d", ret);
			goto err_out;
		}

		drm_sched_start(&hwctx->sched, true);
		XDNA_DBG(xdna, "%s restarted", hwctx->name);
	}
	mutex_unlock(&client->hwctx_lock);
	return 0;

err_out:
	mutex_unlock(&client->hwctx_lock);
	WARN_ON(ret);
	return ret;
}

static int amdxdna_hwctx_wait_for_idle(struct amdxdna_hwctx *hwctx)
{
	struct dma_fence *out_fence;
	signed long remaining;

	spin_lock(&hwctx->io_lock);
	if (!hwctx->seq) {
		spin_unlock(&hwctx->io_lock);
		return 0;
	}

	out_fence = amdxdna_hwctx_get_fence(hwctx, hwctx->seq - 1);
	spin_unlock(&hwctx->io_lock);
	if (!out_fence)
		return 0;

	if (dma_fence_is_signaled(out_fence)) {
		dma_fence_put(out_fence);
		return 0;
	}

	remaining = msecs_to_jiffies(HWCTX_MAX_TIMEOUT);
	remaining = dma_fence_wait_timeout(out_fence, false, remaining);
	dma_fence_put(out_fence);
	WARN_ONCE(!remaining, "Unexpected timeout %ld\n", remaining);

	return (remaining) ? -ETIME : 0;
}

void amdxdna_hwctx_suspend(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0;

	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		/*
		 * Command timeout is unlikely. But if it happens, it doesn't
		 * break the system. ipu_destroy_context() will destroy mailbox
		 * and abort all commands.
		 */
		amdxdna_hwctx_wait_for_idle(hwctx);
		drm_sched_stop(&hwctx->sched, NULL);
		ipu_destroy_context(xdna->dev_handle, hwctx);
	}
	mutex_unlock(&client->hwctx_lock);
}

void amdxdna_hwctx_resume(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0;

	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		/*
		 * The resume path cannot guarantee that mailbox channel can be
		 * regenerated. If this happen, when submit message to this
		 * mailbox channel, error will return.
		 */
		ipu_create_context(xdna->dev_handle, hwctx);
		ipu_config_cu(xdna->dev_handle, hwctx->mbox_chan, hwctx->xclbin);
		drm_sched_start(&hwctx->sched, true);
	}
	mutex_unlock(&client->hwctx_lock);
}

static void amdxdna_hwctx_destroy(struct amdxdna_hwctx *hwctx)
{
	/* Timeout all outstanding jobs */
	drm_sched_fault(&hwctx->sched);
	hwctx->destroyed = true;
	amdxdna_hwctx_wait_for_idle(hwctx);
	amdxdna_hwctx_release(hwctx);
}

/*
 * This should be called in close(). DO NOT call in other syscalls.
 * This guarantee that when hwctx and resources will be released, if user
 * doesn't call amdxdna_drm_destroy_hwctx_ioctl.
 */
void amdxdna_hwctx_remove_all(struct amdxdna_client *client)
{
	struct amdxdna_hwctx *hwctx;
	int next = 0;

	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		XDNA_DBG(client->xdna, "PID %d close HW context %d",
			 client->pid, hwctx->id);
		idr_remove(&client->hwctx_idr, hwctx->id);
		amdxdna_hwctx_destroy(hwctx);
	}
}

int amdxdna_drm_create_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_drm_create_hwctx *args = data;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *heap;
	struct amdxdna_xclbin *xclbin;
	struct amdxdna_qos_info qos_info;
	uuid_t xclbin_uuid;
	int ret, idx;

	if (args->ext_flags)
		return -EINVAL;

	if (sizeof(qos_info) != args->qos_size) {
		XDNA_DBG(xdna, "Invalid QoS info size");
		return -EINVAL;
	}

	if (copy_from_user(&qos_info, u64_to_user_ptr(args->qos_p), sizeof(qos_info))) {
		XDNA_ERR(xdna, "Access QoS info failed");
		return -EFAULT;
	}

	if (!drm_dev_enter(dev, &idx))
		return -ENODEV;

	heap = amdxdna_get_dev_heap(filp);
	if (IS_ERR(heap)) {
		ret = PTR_ERR(heap);
		XDNA_ERR(xdna, "Cannot get dev heap object, ret %d", ret);
		goto out;
	}

	import_uuid(&xclbin_uuid, args->xclbin_uuid);
	mutex_lock(&xdna->dev_lock);
	ret = amdxdna_xclbin_load(xdna, &xclbin_uuid, &xclbin);
	if (ret) {
		XDNA_ERR(xdna, "Unable to register XCLBIN, ret %d", ret);
		goto put_heap;
	}

	ret = amdxdna_hwctx_fill_ip_buf(xclbin, u64_to_user_ptr(args->ip_buf_p),
					args->ip_buf_size);
	if (ret) {
		XDNA_ERR(xdna, "Fill name-index buffer failed, ret %d", ret);
		goto unload_xclbin;
	}

	/*
	 * HW context will be the owner of xclbin cache. The xclbin cache should
	 * be unloaded when HW context is released.
	 */
	ret = amdxdna_hwctx_create(client, xclbin, heap, &qos_info, &args->handle);
	if (ret) {
		XDNA_ERR(xdna, "PID %d create HW context %d failed, ret %d",
			 client->pid, args->handle, ret);
		goto unload_xclbin;
	}
	mutex_unlock(&xdna->dev_lock);

	XDNA_DBG(xdna, "PID %d create HW context %d", client->pid, args->handle);
	drm_dev_exit(idx);
	return 0;

unload_xclbin:
	amdxdna_xclbin_unload(xdna, xclbin);
put_heap:
	mutex_unlock(&xdna->dev_lock);
	drm_gem_object_put(&heap->base);
out:
	drm_dev_exit(idx);
	return ret;
}

int amdxdna_drm_destroy_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_drm_destroy_hwctx *args = data;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_hwctx *hwctx;
	int ret = 0, idx;

	if (!drm_dev_enter(dev, &idx))
		return -ENODEV;

	mutex_lock(&client->hwctx_lock);
	hwctx = idr_find(&client->hwctx_idr, args->handle);
	if (!hwctx) {
		mutex_unlock(&client->hwctx_lock);
		ret = -ENODEV;
		XDNA_DBG(xdna, "PID %d destroy HW context %d failed",
			 client->pid, args->handle);
		goto out;
	}
	idr_remove(&client->hwctx_idr, hwctx->id);
	mutex_unlock(&client->hwctx_lock);

	amdxdna_hwctx_destroy(hwctx);

	XDNA_DBG(xdna, "PID %d destroyed HW context %d", client->pid, args->handle);
out:
	drm_dev_exit(idx);
	return ret;
}

/*
 * The submit command ioctl submits a command to firmware.
 * The command sequence number is returned which can be used for wait command ioctl.
 */
int amdxdna_drm_exec_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_drm_exec_cmd *args = data;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_shmem_obj *sbo;
	struct amdxdna_sched_job *job;
	struct drm_gem_object *gobj;
	struct amdxdna_gem_obj *abo;
	struct amdxdna_hwctx *hwctx;
	int ret, idx;

	if (args->ext_flags)
		return -EINVAL;

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (!gobj) {
		XDNA_ERR(xdna, "Lookup GEM object failed");
		return -ENOENT;
	}
	abo = to_xdna_gem_obj(gobj);

	if (abo->base.size < sizeof(struct amdxdna_start_cmd)) {
		XDNA_ERR(xdna, "Bad cmd BO size: %ld", abo->base.size);
		ret = -EINVAL;
		goto release_bo;
	}

	mutex_lock(&client->mm_lock);
	list_for_each_entry(sbo, &client->shmem_list, entry) {
		if (sbo->pinned)
			continue;

		drm_gem_shmem_pin(&sbo->base);
		sbo->pinned = true;
	}
	mutex_unlock(&client->mm_lock);

	job = kzalloc(sizeof(*job), GFP_KERNEL);
	if (!job) {
		ret = -ENOMEM;
		goto release_bo;
	}

	if (!drm_dev_enter(dev, &idx)) {
		ret = -ENODEV;
		goto free_job;
	}

	hwctx = amdxdna_hwctx_find_by_id(client, args->hwctx);
	if (!hwctx) {
		XDNA_DBG(xdna, "PID %d failed to get hwctx %d",
			 client->pid, args->hwctx);
		ret = -EINVAL;
		goto dev_exit;
	}

	ret = amdxdna_sched_job_init(job, hwctx, abo);
	if (ret) {
		XDNA_ERR(xdna, "failed to init DRM sched job. ret %d", ret);
		goto dev_exit;
	}

	job->out_fence = dma_fence_get(&job->base.s_fence->finished);

	/* Lock all of the shmem objects at once */
	dma_resv_lock(&client->resv, NULL);
	ret = dma_resv_reserve_fences(&client->resv, 1);
	if (ret) {
		XDNA_WARN(xdna, "Failed to reverve fence, ret %d", ret);
		goto unlock_resv;
	}

	dma_resv_add_fence(&client->resv, job->out_fence, DMA_RESV_USAGE_WRITE);
	dma_resv_unlock(&client->resv);

	spin_lock(&hwctx->io_lock);
	if (hwctx->destroyed) {
		ret = -ENODEV;
		goto unlock_and_cleanjob;
	}
	job->seq = amdxdna_hwctx_add_fence(job->hwctx, job->out_fence);
	if (job->seq == AMDXDNA_INVALID_CMD_HANDLE) {
		ret = -EAGAIN;
		goto unlock_and_cleanjob;
	}
	args->seq = job->seq;

	drm_sched_entity_push_job(&job->base);
	spin_unlock(&hwctx->io_lock);
	XDNA_DBG(xdna, "pushed cmd %lld to scheduler", args->seq);

	drm_dev_exit(idx);

	return 0;

unlock_resv:
	dma_resv_unlock(&client->resv);
unlock_and_cleanjob:
	spin_unlock(&hwctx->io_lock);
	dma_fence_put(job->out_fence);
	amdxdna_sched_job_clean(job);
dev_exit:
	drm_dev_exit(idx);
free_job:
	kfree(job);
release_bo:
	drm_gem_object_put(gobj);
	return ret;
}

int amdxdna_drm_wait_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_drm_wait_cmd *args = data;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_hwctx *hwctx;
	struct dma_fence *out_fence;
	signed long remaining = MAX_SCHEDULE_TIMEOUT;
	int ret;

	XDNA_DBG(xdna, "PID %d hwctx %d timeout set %d ms for cmd %lld",
		 client->pid, args->hwctx,
		 args->timeout, args->seq);

	hwctx = amdxdna_hwctx_find_by_id(client, args->hwctx);
	if (!hwctx) {
		XDNA_DBG(xdna, "PID %d failed to get hwctx %d",
			 client->pid, args->hwctx);
		return -EINVAL;
	}

	spin_lock(&hwctx->io_lock);
	if (hwctx->destroyed) {
		spin_unlock(&hwctx->io_lock);
		ret = -ENODEV;
		goto out;
	}
	out_fence = amdxdna_hwctx_get_fence(hwctx, args->seq);
	spin_unlock(&hwctx->io_lock);
	if (IS_ERR(out_fence)) {
		ret = PTR_ERR(out_fence);
		XDNA_ERR(xdna, "Failed to get cmd %lld, ret %d", args->seq, ret);
		goto out;
	}

	if (unlikely(!out_fence)) {
		ret = 0;
		goto out;
	}

	if (dma_fence_is_signaled(out_fence)) {
		ret = 0; /* This command already done */
		goto put_fence;
	}

	if (args->timeout)
		remaining = msecs_to_jiffies(args->timeout);

	remaining = dma_fence_wait_timeout(out_fence, true, remaining);
	if (!remaining)
		ret = -ETIME;
	else if (remaining < 0)
		ret = remaining; /* error code */
	else
		ret = 0;

put_fence:
	dma_fence_put(out_fence);
out:
	XDNA_DBG(xdna, "PID %d hwctx %d cmd %lld wait finished, ret %d",
		 client->pid, args->hwctx, args->seq, ret);
	return ret;
}

#ifdef AMDXDNA_DEVEL
/* HACK: driver gets xclbin from user directly */
int amdxdna_drm_create_hwctx_unsec_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_drm_create_hwctx_unsecure *args = data;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_gem_obj *heap;
	struct amdxdna_xclbin *xclbin;
	struct amdxdna_qos_info qos_info;
	int ret, idx;

	if (sizeof(qos_info) != args->qos_size) {
		XDNA_ERR(xdna, "Invalid QoS info size");
		return -EINVAL;
	}

	if (copy_from_user(&qos_info, u64_to_user_ptr(args->qos_p), sizeof(qos_info))) {
		XDNA_ERR(xdna, "Access QoS info failed");
		return -EFAULT;
	}

	if (!drm_dev_enter(dev, &idx))
		return -ENODEV;

	heap = amdxdna_get_dev_heap(filp);
	if (IS_ERR(heap)) {
		ret = PTR_ERR(heap);
		XDNA_ERR(xdna, "Cannot get dev heap object, ret %d", ret);
		goto out;
	}

	mutex_lock(&xdna->dev_lock);
	ret = amdxdna_xclbin_load_by_ptr(xdna, u64_to_user_ptr(args->xclbin_p), &xclbin);
	if (ret) {
		XDNA_ERR(xdna, "Unable to register XCLBIN, ret %d", ret);
		goto put_heap;
	}

	ret = amdxdna_hwctx_fill_ip_buf(xclbin, u64_to_user_ptr(args->ip_buf_p),
					args->ip_buf_size);
	if (ret) {
		XDNA_ERR(xdna, "Fill name-index buffer failed, ret %d", ret);
		goto unload_xclbin;
	}

	/*
	 * HW context will be the owner of xclbin cache. The xclbin cache should
	 * be unloaded when HW context is released.
	 */
	ret = amdxdna_hwctx_create(client, xclbin, heap, &qos_info, &args->handle);
	if (ret) {
		XDNA_ERR(xdna, "PID %d create HW context %d failed, ret %d",
			 client->pid, args->handle, ret);
		goto unload_xclbin;
	}
	mutex_unlock(&xdna->dev_lock);

	XDNA_DBG(xdna, "PID %d create HW context %d", client->pid, args->handle);
	drm_dev_exit(idx);
	return 0;

unload_xclbin:
	amdxdna_xclbin_unload(xdna, xclbin);
put_heap:
	mutex_unlock(&xdna->dev_lock);
	drm_gem_object_put(&heap->base);
out:
	drm_dev_exit(idx);
	return ret;
}
#endif
