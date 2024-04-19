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
#include "amdxdna_trace.h"

#define MAX_HWCTX_ID		255
#define MAX_ARG_BO_COUNT	4095

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

void amdxdna_hwctx_suspend(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next)
		xdna->dev_info->ops->hwctx_suspend(hwctx);
	mutex_unlock(&client->hwctx_lock);
}

void amdxdna_hwctx_resume(struct amdxdna_client *client)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int next = 0;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	mutex_lock(&client->hwctx_lock);
	idr_for_each_entry_continue(&client->hwctx_idr, hwctx, next)
		xdna->dev_info->ops->hwctx_resume(hwctx);
	mutex_unlock(&client->hwctx_lock);
}

static void amdxdna_hwctx_destroy_rcu(struct amdxdna_hwctx *hwctx,
				      struct srcu_struct *ss)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));
	synchronize_srcu(ss);

	/* At this point, user is not able to submit new commands */
	xdna->dev_info->ops->hwctx_fini(hwctx);

	kfree(hwctx->name);
	kfree(hwctx);
}

/*
 * This should be called in close() and remove(). DO NOT call in other syscalls.
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

int amdxdna_drm_create_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_drm_create_hwctx *args = data;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_hwctx *hwctx;
	int ret, idx;

	if (args->ext_flags)
		return -EINVAL;

	if (!drm_dev_enter(dev, &idx))
		return -ENODEV;

	hwctx = kzalloc(sizeof(*hwctx), GFP_KERNEL);
	if (!hwctx) {
		ret = -ENOMEM;
		goto exit;
	}

	if (copy_from_user(&hwctx->qos, u64_to_user_ptr(args->qos_p), sizeof(hwctx->qos))) {
		XDNA_ERR(xdna, "Access QoS info failed");
		ret = -EFAULT;
		goto free_hwctx;
	}

	hwctx->client = client;
	hwctx->fw_ctx_id = -1;
	hwctx->num_tiles = args->num_tiles;
	hwctx->mem_size = args->mem_size;
	hwctx->max_opc = args->max_opc;
	mutex_lock(&client->hwctx_lock);
	ret = idr_alloc_cyclic(&client->hwctx_idr, hwctx, 0, MAX_HWCTX_ID, GFP_KERNEL);
	if (ret < 0) {
		mutex_unlock(&client->hwctx_lock);
		XDNA_ERR(xdna, "Allocate hwctx ID failed, ret %d", ret);
		goto free_hwctx;
	}
	hwctx->id = ret;
	mutex_unlock(&client->hwctx_lock);

	hwctx->name = kasprintf(GFP_KERNEL, "hwctx.%d.%d", client->pid, hwctx->id);
	if (!hwctx->name) {
		ret = -ENOMEM;
		goto rm_id;
	}

	mutex_lock(&xdna->dev_lock);
	ret = xdna->dev_info->ops->hwctx_init(hwctx);
	if (ret) {
		mutex_unlock(&xdna->dev_lock);
		XDNA_ERR(xdna, "Init hwctx failed, ret %d", ret);
		goto free_name;
	}
	args->handle = hwctx->id;
	mutex_unlock(&xdna->dev_lock);

	XDNA_DBG(xdna, "PID %d create HW context %d, ret %d", client->pid, args->handle, ret);
	drm_dev_exit(idx);
	return 0;

free_name:
	kfree(hwctx->name);
rm_id:
	mutex_lock(&client->hwctx_lock);
	idr_remove(&client->hwctx_idr, hwctx->id);
	mutex_unlock(&client->hwctx_lock);
free_hwctx:
	kfree(hwctx);
exit:
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
		ret = -EINVAL;
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

int amdxdna_drm_config_hwctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_drm_config_hwctx *args = data;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_hwctx *hwctx;
	int ret, idx;
	u32 buf_size;
	void *buf;
	u64 val;

	if (!xdna->dev_info->ops->hwctx_config)
		return -EOPNOTSUPP;

	val = args->param_val;
	buf_size = args->param_val_size;

	switch (args->param_type) {
	case DRM_AMDXDNA_HWCTX_CONFIG_CU:
		/* For those types that param_val is pointer */
		if (buf_size > PAGE_SIZE) {
			XDNA_ERR(xdna, "Config CU param buffer too large");
			return -E2BIG;
		}

		/* Hwctx needs to keep buf */
		buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;

		if (copy_from_user(buf, u64_to_user_ptr(val), buf_size)) {
			kfree(buf);
			return -EFAULT;
		}

		break;
	case DRM_AMDXDNA_HWCTX_ASSIGN_DBG_BUF:
	case DRM_AMDXDNA_HWCTX_REMOVE_DBG_BUF:
		/* For those types that param_val is a value */
		buf = NULL;
		buf_size = 0;
		break;
	default:
		XDNA_DBG(xdna, "Unknown HW context config type %d", args->param_type);
		return -EINVAL;
	}

	mutex_lock(&xdna->dev_lock);
	idx = srcu_read_lock(&client->hwctx_srcu);
	hwctx = idr_find(&client->hwctx_idr, args->handle);
	if (!hwctx) {
		XDNA_DBG(xdna, "PID %d failed to get hwctx %d", client->pid, args->handle);
		ret = -EINVAL;
		goto unlock_srcu;
	}

	ret = xdna->dev_info->ops->hwctx_config(hwctx, args->param_type, val, buf, buf_size);

unlock_srcu:
	srcu_read_unlock(&client->hwctx_srcu, idx);
	mutex_unlock(&xdna->dev_lock);
	kfree(buf);
	return ret;
}

static void amdxdna_sched_job_release(struct kref *ref)
{
	struct amdxdna_sched_job *job;
	int i;

	job = container_of(ref, struct amdxdna_sched_job, refcnt);

	trace_xdna_job(job->hwctx->name, "job release", job->seq);
	for (i = 0; i < job->bo_cnt; i++)
		drm_gem_object_put(job->bos[i]);
	drm_gem_object_put(to_gobj(job->cmd_abo));
	kfree(job);
}

void amdxdna_job_put(struct amdxdna_sched_job *job)
{
	kref_put(&job->refcnt, amdxdna_sched_job_release);
}

static inline void
amdxdna_arg_bos_put(struct amdxdna_sched_job *job)
{
	int i;

	for (i = 0; i < job->bo_cnt; i++) {
		if (!job->bos[i])
			break;
		drm_gem_object_put(job->bos[i]);
	}
}

static inline int
amdxdna_arg_bos_lookup(struct amdxdna_client *client,
		       struct amdxdna_sched_job *job,
		       u32 *bo_hdls, u32 bo_cnt)
{
	struct drm_gem_object *gobj;
	int i, ret;

	job->bo_cnt = bo_cnt;
	for (i = 0; i < job->bo_cnt; i++) {
		struct amdxdna_gem_obj *abo;

		gobj = drm_gem_object_lookup(client->filp, bo_hdls[i]);
		if (!gobj) {
			ret = -ENOENT;
			goto put_shmem_bo;
		}
		abo = to_xdna_obj(gobj);

		mutex_lock(&abo->lock);
		if (abo->pinned) {
			mutex_unlock(&abo->lock);
			job->bos[i] = gobj;
			continue;
		}

		ret = amdxdna_gem_pin_nolock(abo);
		if (ret) {
			mutex_unlock(&abo->lock);
			drm_gem_object_put(gobj);
			goto put_shmem_bo;
		}
		abo->pinned = true;
		mutex_unlock(&abo->lock);

		job->bos[i] = gobj;
	}

	return 0;

put_shmem_bo:
	amdxdna_arg_bos_put(job);
	return ret;
}

static int amdxdna_cmds_submit(struct amdxdna_client *client,
			       struct amdxdna_gem_obj *cmd_bo, u32 *bo_hdls,
			       struct amdxdna_drm_exec_cmd *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	u32 bo_cnt = args->arg_bo_count;
	struct amdxdna_sched_job *job;
	struct amdxdna_hwctx *hwctx;
	u32 *cu_mask;
	int ret, idx;
	int i;

	job = kzalloc(struct_size(job, bos, bo_cnt), GFP_KERNEL);
	if (!job)
		return -ENOMEM;

	ret = amdxdna_arg_bos_lookup(client, job, bo_hdls, bo_cnt);
	if (ret) {
		XDNA_ERR(xdna, "Argument BOs lookup failed, ret %d", ret);
		goto free_job;
	}

	idx = srcu_read_lock(&client->hwctx_srcu);
	hwctx = idr_find(&client->hwctx_idr, args->hwctx);
	if (!hwctx) {
		XDNA_DBG(xdna, "PID %d failed to get hwctx %d",
			 client->pid, args->hwctx);
		ret = -EINVAL;
		goto unlock_srcu;
	}

	if (hwctx->status != HWCTX_STAT_READY) {
		XDNA_ERR(xdna, "HW Context is not ready");
		ret = -EINVAL;
		goto unlock_srcu;
	}

	job->cmd_abo = cmd_bo;
	job->cmd = cmd_bo->mem.kva;
	if (!job->cmd) {
		XDNA_ERR(xdna, "Cmd KVA not found");
		ret = -EINVAL;
		goto unlock_srcu;
	}

	if (to_gobj(cmd_bo)->size <
	    offsetof(struct amdxdna_cmd, data[job->cmd->extra_cu_masks])) {
		XDNA_DBG(xdna, "Invalid extra_cu_masks");
		ret = -EINVAL;
		goto unlock_srcu;
	}

	job->cmd->state = ERT_CMD_STATE_NEW;
	job->hwctx = hwctx;
	job->mm = current->mm;

	cu_mask = &job->cmd->cu_mask;
	for (i = 0; i < 1 + job->cmd->extra_cu_masks; i++) {
		job->cu_idx = ffs(cu_mask[i]) - 1;

		if (job->cu_idx >= 0)
			break;
	}
	if (job->cu_idx < 0) {
		ret = -EINVAL;
		goto unlock_srcu;
	}

	job->fence = amdxdna_fence_create(hwctx);
	if (!job->fence) {
		XDNA_ERR(xdna, "Failed to create fence");
		ret = -ENOMEM;
		goto unlock_srcu;
	}
	kref_init(&job->refcnt);

	ret = xdna->dev_info->ops->cmd_submit(hwctx, job, &args->seq);
	if (ret)
		goto put_fence;

	/*
	 * The amdxdna_hwctx_destroy_rcu() will release hwctx and associated
	 * resource after synchronize_srcu(). The submitted jobs should be
	 * handled by the queue, for example DRM scheduler, in device layer.
	 * For here we can unlock SRCU.
	 */
	srcu_read_unlock(&client->hwctx_srcu, idx);
	trace_xdna_job(hwctx->name, "job pushed", args->seq);

	return 0;

put_fence:
	dma_fence_put(job->fence);
unlock_srcu:
	srcu_read_unlock(&client->hwctx_srcu, idx);
	amdxdna_arg_bos_put(job);
free_job:
	kfree(job);
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
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_exec_cmd *args = data;
	struct amdxdna_gem_obj *cmd_bo;
	u32 cmd_bo_hdl;
	u32 *bo_hdls;
	int ret;

	if (args->ext_flags)
		return -EINVAL;

	if (!args->arg_bo_count || args->arg_bo_count > MAX_ARG_BO_COUNT)
		return -EINVAL;

	if (args->cmd_bo_count != 1) {
		XDNA_ERR(xdna, "Command list is not supported yet");
		return -EOPNOTSUPP;
	}
	ret = copy_from_user(&cmd_bo_hdl, u64_to_user_ptr(args->cmd_bo_handles), sizeof(u32));
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

	cmd_bo = amdxdna_gem_get_obj(dev, cmd_bo_hdl, AMDXDNA_BO_CMD, filp);
	if (!cmd_bo) {
		XDNA_DBG(xdna, "get cmd bo failed");
		ret = -ENOENT;
		goto free_bo_hdls;
	}

	if (to_gobj(cmd_bo)->size < sizeof(struct amdxdna_cmd)) {
		XDNA_DBG(xdna, "Bad cmd BO size: %ld", to_gobj(cmd_bo)->size);
		ret = -EINVAL;
		goto put_cmd_bo;
	}

	ret = amdxdna_cmds_submit(client, cmd_bo, bo_hdls, args);
	if (ret) {
		XDNA_DBG(xdna, "Submit cmds failed, ret %d", ret);
		goto put_cmd_bo;
	}

	kfree(bo_hdls);
	XDNA_DBG(xdna, "pushed cmd %lld to scheduler", args->seq);

	return 0;

put_cmd_bo:
	drm_gem_object_put(to_gobj(cmd_bo));
free_bo_hdls:
	kfree(bo_hdls);
	return ret;
}

int amdxdna_drm_wait_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_wait_cmd *args = data;
	struct amdxdna_hwctx *hwctx;
	int ret, idx;

	XDNA_DBG(xdna, "PID %d hwctx %d timeout set %d ms for cmd %lld",
		 client->pid, args->hwctx, args->timeout, args->seq);

	if (!xdna->dev_info->ops->cmd_wait)
		return -EOPNOTSUPP;

	/* For locking concerns, see amdxdna_drm_exec_cmd_ioctl. */
	idx = srcu_read_lock(&client->hwctx_srcu);
	hwctx = idr_find(&client->hwctx_idr, args->hwctx);
	if (!hwctx) {
		XDNA_DBG(xdna, "PID %d failed to get hwctx %d",
			 client->pid, args->hwctx);
		ret = -EINVAL;
		goto unlock_hwctx_srcu;
	}

	ret = xdna->dev_info->ops->cmd_wait(hwctx, args->seq, args->timeout);
	XDNA_DBG(xdna, "PID %d hwctx %d cmd %lld wait finished, ret %d",
		 client->pid, args->hwctx, args->seq, ret);

unlock_hwctx_srcu:
	srcu_read_unlock(&client->hwctx_srcu, idx);
	return ret;
}
