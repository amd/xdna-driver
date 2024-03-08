// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#include <linux/version.h>
#include <linux/kref.h>
#include <drm/drm_file.h>
#include <drm/drm_cache.h>
#include "drm_local/amdxdna_accel.h"

#include "amdxdna_drv.h"
#include "amdxdna_ctx.h"
#include "amdxdna_xclbin.h"
#include "npu_pci.h"

#define MAX_HWCTX_ID		255
#define MAX_ARG_BO_COUNT	4095

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
struct amdxdna_cmd {
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
	struct mm_struct	*mm;
	/* The fence to notice DRM scheduler that job is done by hardware */
	struct dma_fence	*fence;
	/* user can wait on this fence */
	struct dma_fence	*out_fence;
	u32			cu_idx;
	struct amdxdna_cmd	*cmd;
	struct amdxdna_gem_obj	*cmd_abo;
	u64			seq;
	size_t			bo_cnt;
	struct drm_gem_object	*bos[] __counted_by(bo_cnt);
};

struct amdxdna_fence {
	struct dma_fence	base;
	spinlock_t		lock; /* for base */
	struct amdxdna_hwctx	*hwctx;
};

static const char *amdxdna_fence_get_driver_name(struct dma_fence *fence)
{
	return KBUILD_MODNAME;
}

static const char *amdxdna_fence_get_timeline_name(struct dma_fence *fence)
{
	struct amdxdna_fence *xdna_fence;

	xdna_fence = container_of(fence, struct amdxdna_fence, base);

	return xdna_fence->hwctx->name;
}

static const struct dma_fence_ops fence_ops = {
	.get_driver_name = amdxdna_fence_get_driver_name,
	.get_timeline_name = amdxdna_fence_get_timeline_name,
};

static struct dma_fence *amdxdna_fence_create(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_fence *fence;

	fence = kzalloc(sizeof(*fence), GFP_KERNEL);
	if (!fence)
		return NULL;

	fence->hwctx = hwctx;
	spin_lock_init(&fence->lock);
	dma_fence_init(&fence->base, &fence_ops, &fence->lock, hwctx->id, 0);
	return &fence->base;
}

static void amdxdna_sched_job_release(struct kref *ref)
{
	struct amdxdna_sched_job *job;
	int i;

	job = container_of(ref, struct amdxdna_sched_job, refcnt);

	for (i = 0; i < job->bo_cnt; i++)
		drm_gem_object_put(job->bos[i]);
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

	if (abo->base.size <
	    offsetof(struct amdxdna_cmd, data[job->cmd->extra_cu_masks])) {
		XDNA_DBG(xdna, "invalid extra_cu_masks");
		return -EINVAL;
	}

	job->cmd->state = ERT_CMD_STATE_NEW;
	job->hwctx = hwctx;
	job->mm = current->mm;

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

	ret = drm_sched_job_init(&job->base, &hwctx->entity, 1, hwctx);
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
	mmput(job->mm);
	amdxdna_job_put(job);
}

static struct dma_fence *
amdxdna_sched_job_run(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);
	struct amdxdna_hwctx *hwctx = job->hwctx;
	struct amdxdna_dev *xdna;
	struct dma_fence *fence;
	void *cmd_buf;
	u32 buf_len;
	int ret;

	xdna = hwctx->client->xdna;

	if (!mmget_not_zero(job->mm))
		return ERR_PTR(-ESRCH);

	kref_get(&job->refcnt);
	fence = dma_fence_get(job->fence);
	cmd_buf = &job->cmd->data[job->cmd->extra_cu_masks];
	buf_len = job->cmd_abo->base.size -
		offsetof(struct amdxdna_cmd, data[job->cmd->extra_cu_masks]);
	ret = npu_execbuf(xdna->dev_handle, hwctx->mbox_chan, job->cu_idx,
			  cmd_buf, buf_len, job, amdxdna_sched_resp_handler);
	if (ret) {
		dma_fence_put(job->fence);
		amdxdna_job_put(job);
		mmput(job->mm);
		fence = ERR_PTR(ret);
	}

	return fence;
}

static void amdxdna_sched_job_free(struct drm_sched_job *sched_job)
{
	struct amdxdna_sched_job *job = drm_job_to_xdna_job(sched_job);

	drm_sched_job_cleanup(sched_job);
	amdxdna_job_put(job);
}

static const struct drm_sched_backend_ops sched_ops = {
	.run_job = amdxdna_sched_job_run,
	.free_job = amdxdna_sched_job_free,
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

	ret = npu_release_resource(hwctx);
	if (ret)
		XDNA_ERR(xdna, "release hw resource failed, ret %d", ret);

	XDNA_DBG(xdna, "hwctx %s cleanup completed", hwctx->name);
}

static int amdxdna_hwctx_init(struct amdxdna_hwctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	int ret;

	ret = npu_alloc_resource(hwctx);
	if (ret) {
		XDNA_ERR(xdna, "alloc hw resource failed, ret %d", ret);
		goto out;
	}

	XDNA_DBG(xdna, "hwctx %s init completed", hwctx->name);

	ret = npu_config_cu(xdna->dev_handle, hwctx->mbox_chan, hwctx->xclbin);
	if (ret) {
		XDNA_ERR(xdna, "Config CU failed, ret %d", ret);
		goto release_resource;
	}

	return 0;

release_resource:
	npu_release_resource(hwctx);
out:
	return ret;
}

static void amdxdna_hwctx_release(struct amdxdna_hwctx *hwctx)
{
	struct dma_fence *fence;
	struct amdxdna_dev *xdna;
	int idx;

	xdna = hwctx->client->xdna;
	amdxdna_hwctx_cleanup(hwctx);
	amdxdna_xclbin_unload(xdna, hwctx->xclbin);
	drm_sched_entity_destroy(&hwctx->entity);
	drm_sched_fini(&hwctx->sched);

	for (idx = 0; idx < HWCTX_MAX_CMDS; idx++) {
		fence = hwctx->pending[idx];
		if (!fence)
			continue;

		dma_fence_put(fence);
	}
	XDNA_DBG(xdna, "%s sequence number %lld", hwctx->name, hwctx->seq);

	mutex_lock(&hwctx->client->mm_lock);
	amdxdna_unpin_pages(&hwctx->heap->mem);
	mutex_unlock(&hwctx->client->mm_lock);
	amdxdna_put_dev_heap(hwctx->heap);
	kfree(hwctx->name);
	kfree(hwctx);
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

	mutex_lock(&client->mm_lock);
	ret = amdxdna_pin_pages(&heap->mem);
	mutex_unlock(&client->mm_lock);
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

	sched = &hwctx->sched;
	ret = drm_sched_init(sched, &sched_ops, NULL, DRM_SCHED_PRIORITY_COUNT,
			     HWCTX_MAX_CMDS, 0, MAX_SCHEDULE_TIMEOUT, NULL,
			     NULL, hwctx->name, &client->xdna->pdev->dev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init DRM scheduler. ret %d", ret);
		goto free_name;
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

	ret = npu_map_host_buf(xdna->dev_handle, hwctx->fw_ctx_id,
			       heap->mem.userptr, heap->mem.size);
	if (ret) {
		XDNA_ERR(xdna, "Map host buffer failed, ret %d", ret);
		goto hwctx_cleanup;
	}

	*hwctx_id = hwctx->id;

	return 0;

hwctx_cleanup:
	amdxdna_hwctx_cleanup(hwctx);
free_entity:
	drm_sched_entity_destroy(&hwctx->entity);
free_sched:
	drm_sched_fini(&hwctx->sched);
free_name:
	kfree(hwctx->name);
rm_id:
	idr_remove(&client->hwctx_idr, hwctx->id);
free_hwctx:
	kfree(hwctx);
unpin:
	mutex_lock(&client->mm_lock);
	amdxdna_unpin_pages(&heap->mem);
	mutex_unlock(&client->mm_lock);
	return ret;
}

static int amdxdna_hwctx_col_match(struct amdxdna_hwctx *hwctx, u32 col_map)
{
	u32 start_col, end_col;

	start_col = hwctx->start_col;
	end_col = start_col + hwctx->num_col - 1;

	return col_map & GENMASK(end_col, start_col);
}

void amdxdna_stop_ctx_by_col_map(struct amdxdna_client *client, u32 col_map)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0, ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		/* check if the HW context uses the error column */
		if (!amdxdna_hwctx_col_match(hwctx, col_map))
			continue;
		hwctx->stopped = true;
		XDNA_DBG(xdna, "Stop %s.%d", hwctx->name, hwctx->id);

		drm_sched_stop(&hwctx->sched, NULL);
		ret = npu_destroy_context(xdna->dev_handle, hwctx);
		if (ret)
			XDNA_ERR(xdna, "Destroy hwctx failed, ret %d", ret);
	}
	mutex_unlock(&client->hwctx_lock);
}

void amdxdna_restart_ctx(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0, ret;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		if (!hwctx->stopped)
			continue;

		XDNA_DBG(xdna, "Resetting %s.%d", hwctx->name, hwctx->id);
		ret = npu_create_context(xdna->dev_handle, hwctx);
		if (ret) {
			XDNA_ERR(xdna, "Create hwctx failed, ret %d", ret);
			continue;
		}

		ret = npu_config_cu(xdna->dev_handle, hwctx->mbox_chan, hwctx->xclbin);
		if (ret) {
			XDNA_ERR(xdna, "Config cu failed, ret %d", ret);
			continue;
		}

		drm_sched_start(&hwctx->sched, true);
		hwctx->stopped = false;
		XDNA_DBG(xdna, "%s.%d restarted", hwctx->name, hwctx->id);
	}
	mutex_unlock(&client->hwctx_lock);
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

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		/*
		 * Command timeout is unlikely. But if it happens, it doesn't
		 * break the system. npu_destroy_context() will destroy mailbox
		 * and abort all commands.
		 */
		amdxdna_hwctx_wait_for_idle(hwctx);
		drm_sched_stop(&hwctx->sched, NULL);
		npu_destroy_context(xdna->dev_handle, hwctx);
		npu_unregister_pdis(xdna->dev_handle, hwctx->xclbin);
	}
	mutex_unlock(&client->hwctx_lock);
}

void amdxdna_hwctx_resume(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		/*
		 * The resume path cannot guarantee that mailbox channel can be
		 * regenerated. If this happen, when submit message to this
		 * mailbox channel, error will return.
		 */
		npu_register_pdis(xdna->dev_handle, hwctx->xclbin);
		npu_create_context(xdna->dev_handle, hwctx);
		npu_config_cu(xdna->dev_handle, hwctx->mbox_chan, hwctx->xclbin);
		drm_sched_start(&hwctx->sched, true);
	}
	mutex_unlock(&client->hwctx_lock);
}

static void populate_hwctx(struct amdxdna_drm_query_hwctx *hwctx_user,
			   struct amdxdna_hwctx *hwctx, pid_t pid)
{
	hwctx_user->pid = pid;
	hwctx_user->context_id = hwctx->id;
	hwctx_user->start_col = hwctx->start_col;
	hwctx_user->num_col = hwctx->num_col;
	hwctx_user->command_submissions = hwctx->seq;
	/* TODO Not implemented section */
	hwctx_user->command_completions = 0;
	hwctx_user->migrations = 0;
	hwctx_user->preemptions = 0;
	hwctx_user->errors = 0;
}

int amdxdna_hwctx_status(struct drm_device *dev, u32 *buf_size,
			 struct amdxdna_drm_query_hwctx __user *buf)
{
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_client *client, *tmp_client;
	struct amdxdna_drm_query_hwctx *hwctx_user;
	struct amdxdna_hwctx *hwctx;
	bool overflow = false;
	u32 req_bytes = 0;
	u32 hw_i = 0;
	int next = 0;
	int ret = 0;
	int idx;

	hwctx_user = kzalloc(sizeof(*hwctx_user), GFP_KERNEL);
	if (!hwctx_user) {
		ret = -ENOMEM;
		goto fail;
	}

	mutex_lock(&xdna->dev_lock);
	list_for_each_entry_safe(client, tmp_client, &xdna->client_list, node) {
		idx = srcu_read_lock(&client->hwctx_srcu);
		idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
			req_bytes += sizeof(*hwctx_user);
			if (*buf_size < req_bytes) {
				/* Continue iterating to get the required size */
				overflow = true;
				continue;
			}

			populate_hwctx(hwctx_user, hwctx, client->pid);

			if (copy_to_user(&buf[hw_i], hwctx_user, sizeof(*hwctx_user))) {
				ret = -EFAULT;
				goto fail_copy;
			}
			hw_i++;
		}
		srcu_read_unlock(&client->hwctx_srcu, idx);
	}
	mutex_unlock(&xdna->dev_lock);

	if (overflow) {
		XDNA_ERR(xdna, "Invalid buffer size. Given: %u Need: %u.",
			 *buf_size, req_bytes);
		ret = -EINVAL;
	}

	kfree(hwctx_user);
	*buf_size = req_bytes;
	return ret;

fail_copy:
	srcu_read_unlock(&client->hwctx_srcu, idx);
	mutex_unlock(&xdna->dev_lock);
	kfree(hwctx_user);
fail:
	*buf_size = req_bytes;
	return ret;
}

static void amdxdna_hwctx_destroy_rcu(struct amdxdna_hwctx *hwctx,
				      struct srcu_struct *ss)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	synchronize_srcu(ss);

	/* At this point, user is not able to submit new commands */
	drm_sched_wqueue_stop(&hwctx->sched);

	/* Now, scheduler will not send command to device. */
	npu_destroy_context(xdna->dev_handle, hwctx);

	/*
	 * All submitted commands are aborted.
	 * Restart scheduler queues to cleanup jobs. The amdxdna_sched_job_run()
	 * will return NODEV if it is called.
	 */
	drm_sched_wqueue_start(&hwctx->sched);
	amdxdna_hwctx_release(hwctx);
}

/*
 * This should be called in close(). DO NOT call in other syscalls.
 * This guarantee that when hwctx and resources will be released, if user
 * doesn't call amdxdna_drm_destroy_hwctx_ioctl.
 */
void amdxdna_hwctx_remove_all(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next) {
		XDNA_DBG(client->xdna, "PID %d close HW context %d",
			 client->pid, hwctx->id);
		idr_remove(&client->hwctx_idr, hwctx->id);
		mutex_unlock(&client->hwctx_lock);
		amdxdna_hwctx_destroy_rcu(hwctx, &client->hwctx_srcu);
		mutex_lock(&client->hwctx_lock);
	}
	mutex_unlock(&client->hwctx_lock);
}

int amdxdna_drm_create_hwctx_legacy_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_drm_create_hwctx_legacy *args = data;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_qos_info qos_info;
	struct amdxdna_xclbin *xclbin;
	struct amdxdna_gem_obj *heap;
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
	amdxdna_put_dev_heap(heap);
out:
	drm_dev_exit(idx);
	return ret;
}

int amdxdna_drm_create_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
    return -EOPNOTSUPP;
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

	/*
	 * Use hwctx_lock to achieve exclusion with other hwctx writers.
	 * Such as, stop/restart, suspend/resume context and remove device.
	 *
	 * Use SRCU to synchronize with exec/wait command ioctls.
	 *
	 * The pushed jobs are handled by DRM scheduler during destroy.
	 */
	mutex_lock(&client->hwctx_lock);
	hwctx = idr_find(&client->hwctx_idr, args->handle);
	if (!hwctx) {
		mutex_unlock(&client->hwctx_lock);
		ret = -ENODEV;
		XDNA_DBG(xdna, "PID %d HW context %d not exist",
			 client->pid, args->handle);
		goto out;
	}
	idr_remove(&client->hwctx_idr, hwctx->id);
	mutex_unlock(&client->hwctx_lock);

	mutex_lock(&xdna->dev_lock);
	amdxdna_hwctx_destroy_rcu(hwctx, &client->hwctx_srcu);
	mutex_unlock(&xdna->dev_lock);

out:
	drm_dev_exit(idx);
	XDNA_DBG(xdna, "PID %d destroyed HW context %d", client->pid, args->handle);
	return ret;
}

/*
 * The submit command ioctl submits a command to firmware. One firmware command
 * may contain multiple command BOs for processing as a whole.
 * The command sequence number is returned which can be used for wait command ioctl.
 */
int amdxdna_drm_exec_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_drm_exec_cmd *args = data;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct ww_acquire_ctx acquire_ctx;
	struct amdxdna_gem_shmem_obj *sbo;
	struct amdxdna_sched_job *job;
	struct drm_gem_object *gobj;
	struct amdxdna_gem_obj *abo;
	struct amdxdna_hwctx *hwctx;
	enum amdxdna_obj_type type;
	u32 *bo_hdls;
	int ret, idx;
	u32 cmd_bo;
	int i;

	if (args->ext_flags)
		return -EINVAL;

	if (!args->arg_bo_count || args->arg_bo_count > MAX_ARG_BO_COUNT)
		return -EINVAL;

	if (args->cmd_bo_count != 1) {
		XDNA_ERR(xdna, "Command list is not supported yet");
		return -EOPNOTSUPP;
	}
	ret = copy_from_user(&cmd_bo, u64_to_user_ptr(args->cmd_bo_handles), sizeof(u32));
	if (ret)
		return -EFAULT;

	bo_hdls = kcalloc(args->arg_bo_count, sizeof(u32), GFP_KERNEL);
	if (!bo_hdls)
		return -ENOMEM;

	ret = copy_from_user(bo_hdls, u64_to_user_ptr(args->arg_bo_handles),
			     args->arg_bo_count * sizeof(u32));
	if (ret) {
		ret = -EFAULT;
		goto free_bo_hdls;
	}

	/*
	 * SRCU lock for synchronizing with amdxdna_hwctx_destroy_rcu().
	 * I don't worry about concurrently stop/restart context. Because this
	 * ioctl just create job and push it to DRM's queue. When stop/restart
	 * context, DRM scheduler has protection for the jobs in its queue.
	 *
	 * Just make sure before this ioctl exited, don't release context.
	 */
	idx = srcu_read_lock(&client->hwctx_srcu);

	gobj = drm_gem_object_lookup(filp, cmd_bo);
	if (!gobj) {
		XDNA_ERR(xdna, "Lookup GEM object failed");
		ret = -ENOENT;
		goto unlock_hwctx_srcu;
	}

	type = amdxdna_gem_get_obj_type(gobj);
	if (unlikely(type != AMDXDNA_GEM_OBJ)) {
		XDNA_ERR(xdna, "Invalid exec cmd BO type %d", type);
		ret = -EINVAL;
		goto release_cmd_obj;
	}
	abo = to_xdna_gem_obj(gobj);

	if (abo->base.size < sizeof(struct amdxdna_cmd)) {
		XDNA_ERR(xdna, "Bad cmd BO size: %ld", abo->base.size);
		ret = -EINVAL;
		goto release_cmd_obj;
	}

	job = kzalloc(struct_size(job, bos, args->arg_bo_count), GFP_KERNEL);
	if (!job) {
		ret = -ENOMEM;
		goto release_cmd_obj;
	}

	job->bo_cnt = args->arg_bo_count;
	for (i = 0; i < job->bo_cnt; i++) {
		struct drm_gem_object *gobj = drm_gem_object_lookup(filp, bo_hdls[i]);

		if (!gobj) {
			ret = -ENOENT;
			goto free_job;
		}

		job->bos[i] = gobj;

		type = amdxdna_gem_get_obj_type(gobj);
		switch (type) {
		case AMDXDNA_SHMEM_OBJ:
			sbo = to_xdna_gem_shmem_obj(gobj);
			if (sbo->pinned)
				continue;

			/*
			 * Pin the backing physical pages.
			 *
			 * Note: Unpin the backing physical pages when free object.
			 * When job is released, only put this object.
			 * See amdxdna_gem_shmem_free().
			 */
			drm_gem_shmem_pin(&sbo->base);
			sbo->pinned = true;
			break;
		default:
			/*
			 * For AMDXDNA_GEM_OBJ, don't need to pin.
			 * If lookup a unknown type object, that should be a bug.
			 */
			drm_WARN_ON(&xdna->ddev, type == AMDXDNA_UNKNOWN_OBJ);
		}
	}

	hwctx = idr_find(&client->hwctx_idr, args->hwctx);
	if (!hwctx) {
		XDNA_DBG(xdna, "PID %d failed to get hwctx %d",
			 client->pid, args->hwctx);
		ret = -EINVAL;
		goto free_job;
	}

	ret = amdxdna_sched_job_init(job, hwctx, abo);
	if (ret) {
		XDNA_ERR(xdna, "failed to init DRM sched job. ret %d", ret);
		goto free_job;
	}

	job->out_fence = dma_fence_get(&job->base.s_fence->finished);

	ret = drm_gem_lock_reservations(job->bos, job->bo_cnt, &acquire_ctx);
	if (ret) {
		XDNA_WARN(xdna, "Failed to reverve fence, ret %d", ret);
		goto put_fence;
	}

	for (i = 0; i < job->bo_cnt; i++) {
		ret = dma_resv_reserve_fences(job->bos[i]->resv, 1);
		if (ret) {
			XDNA_WARN(xdna, "Failed to reserve fences %d", ret);
			goto unlock_resv;
		}
	}

	for (i = 0; i < job->bo_cnt; i++)
		dma_resv_add_fence(job->bos[i]->resv, job->out_fence, DMA_RESV_USAGE_WRITE);
	drm_gem_unlock_reservations(job->bos, job->bo_cnt, &acquire_ctx);

	spin_lock(&hwctx->io_lock);
	job->seq = amdxdna_hwctx_add_fence(job->hwctx, job->out_fence);
	if (job->seq == AMDXDNA_INVALID_CMD_HANDLE) {
		ret = -EAGAIN;
		goto unlock_io;
	}
	args->seq = job->seq;

	drm_sched_entity_push_job(&job->base);
	spin_unlock(&hwctx->io_lock);
	/*
	 * The amdxdna_hwctx_destroy_rcu() will destroy DRM sched entity
	 * after synchronize_srcu(). DRM sched will handle pushed jobs. Now we
	 * can unlock SRCU.
	 */
	srcu_read_unlock(&client->hwctx_srcu, idx);
	kfree(bo_hdls);
	XDNA_DBG(xdna, "pushed cmd %lld to scheduler", args->seq);

	return 0;

unlock_io:
	spin_unlock(&hwctx->io_lock);
unlock_resv:
	drm_gem_unlock_reservations(job->bos, job->bo_cnt, &acquire_ctx);
put_fence:
	dma_fence_put(job->out_fence);
	amdxdna_sched_job_clean(job);
free_job:
	for (i = 0; i < job->bo_cnt; i++) {
		if (!job->bos[i])
			continue;
		drm_gem_object_put(job->bos[i]);
	}
	kfree(job);
release_cmd_obj:
	drm_gem_object_put(gobj);
unlock_hwctx_srcu:
	srcu_read_unlock(&client->hwctx_srcu, idx);
free_bo_hdls:
	kfree(bo_hdls);
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
	int ret, idx;

	XDNA_DBG(xdna, "PID %d hwctx %d timeout set %d ms for cmd %lld",
		 client->pid, args->hwctx, args->timeout, args->seq);

	/* For locking concerns, see amdxdna_drm_exec_cmd_ioctl. */
	idx = srcu_read_lock(&client->hwctx_srcu);
	hwctx = idr_find(&client->hwctx_idr, args->hwctx);
	if (!hwctx) {
		XDNA_DBG(xdna, "PID %d failed to get hwctx %d",
			 client->pid, args->hwctx);
		ret = -EINVAL;
		goto unlock_hwctx_srcu;
	}

	spin_lock(&hwctx->io_lock);
	out_fence = amdxdna_hwctx_get_fence(hwctx, args->seq);
	spin_unlock(&hwctx->io_lock);
	srcu_read_unlock(&client->hwctx_srcu, idx);
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

unlock_hwctx_srcu:
	srcu_read_unlock(&client->hwctx_srcu, idx);
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
	amdxdna_put_dev_heap(heap);
out:
	drm_dev_exit(idx);
	return ret;
}
#endif
