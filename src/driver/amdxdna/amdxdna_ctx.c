// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#include <linux/version.h>
#include <linux/kref.h>
#include <drm/drm_file.h>
#include <drm/drm_cache.h>
#include "drm_local/amdxdna_accel.h"

#include "amdxdna_drm.h"
#include "amdxdna_ctx.h"
#include "amdxdna_trace.h"

#define MAX_HWCTX_ID		255
#define MAX_ARG_COUNT		4095

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

	synchronize_srcu(ss);

	/* At this point, user is not able to submit new commands */
	mutex_lock(&xdna->dev_lock);
	xdna->dev_info->ops->hwctx_fini(hwctx);
	mutex_unlock(&xdna->dev_lock);

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
	struct amdxdna_hwctx *hwctx;
	int next = 0;

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
	hwctx->tdr_last_completed = -1;
	hwctx->num_tiles = args->num_tiles;
	hwctx->mem_size = args->mem_size;
	hwctx->max_opc = args->max_opc;
	hwctx->umq_bo = args->umq_bo;
	hwctx->log_buf_bo = args->log_buf_bo;
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
	args->umq_doorbell = hwctx->doorbell_offset;
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

	amdxdna_hwctx_destroy_rcu(hwctx, &client->hwctx_srcu);

	XDNA_DBG(xdna, "PID %d destroyed HW context %d", client->pid, args->handle);
out:
	drm_dev_exit(idx);
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
			goto put_arg_bos;
		}
		abo = to_xdna_obj(gobj);

		mutex_lock(&abo->lock);
		if (abo->flags & BO_SUBMIT_PINNED) {
			mutex_unlock(&abo->lock);
			job->bos[i] = gobj;
			continue;
		}

		ret = amdxdna_gem_pin_nolock(abo);
		if (ret) {
			mutex_unlock(&abo->lock);
			drm_gem_object_put(gobj);
			goto put_arg_bos;
		}
		abo->flags |= BO_SUBMIT_PINNED;
		mutex_unlock(&abo->lock);

		job->bos[i] = gobj;
	}

	return 0;

put_arg_bos:
	amdxdna_arg_bos_put(job);
	return ret;
}

static void amdxdna_sched_job_release(struct kref *ref)
{
	struct amdxdna_sched_job *job;

	job = container_of(ref, struct amdxdna_sched_job, refcnt);

	trace_amdxdna_debug_point(job->hwctx->name, job->seq, "job release");
	amdxdna_arg_bos_put(job);
	amdxdna_gem_put_obj(job->cmd_bo);
	kfree(job);
}

void amdxdna_job_put(struct amdxdna_sched_job *job)
{
	kref_put(&job->refcnt, amdxdna_sched_job_release);
}

int amdxdna_lock_objects(struct amdxdna_sched_job *job, struct ww_acquire_ctx *ctx)
{
	struct amdxdna_dev *xdna = job->hwctx->client->xdna;
	struct amdxdna_gem_obj *abo;
	int contended = -1, i, ret;

	ww_acquire_init(ctx, &reservation_ww_class);

retry:
	if (contended != -1) {
		ret = dma_resv_lock_slow_interruptible(job->bos[contended]->resv, ctx);
		if (ret) {
			ww_acquire_fini(ctx);
			return ret;
		}
		abo->flags |= BO_SUBMIT_LOCKED;
	}

	for (i = 0; i < job->bo_cnt; i++) {
		abo = to_xdna_obj(job->bos[i]);
		if (abo->flags & BO_SUBMIT_LOCKED)
			continue;

		ret = dma_resv_lock_interruptible(job->bos[i]->resv, ctx);
		if (ret) {
			int j;

			for (j = 0; j < i; j++) {
				abo = to_xdna_obj(job->bos[j]);
				dma_resv_unlock(job->bos[j]->resv);
				abo->flags &= ~BO_SUBMIT_LOCKED;
			}

			if (contended != -1 && contended >= i)
				dma_resv_unlock(job->bos[contended]->resv);

			if (ret == -EDEADLK) {
				contended = i;
				goto retry;
			}

			ww_acquire_fini(ctx);

			XDNA_ERR(xdna, "Lock BO failed, ret %d", ret);
			return ret;
		}
		abo->flags |= BO_SUBMIT_LOCKED;
	}

	ww_acquire_done(ctx);

	return 0;
}

void amdxdna_unlock_objects(struct amdxdna_sched_job *job, struct ww_acquire_ctx *ctx)
{
	struct amdxdna_gem_obj *abo;
	int i;

	for (i = 0; i < job->bo_cnt; i++) {
		abo = to_xdna_obj(job->bos[i]);
		if (!(abo->flags & BO_SUBMIT_LOCKED))
			continue;

		dma_resv_unlock(job->bos[i]->resv);
		abo->flags &= ~BO_SUBMIT_LOCKED;
	}

	ww_acquire_fini(ctx);
}

int amdxdna_cmd_submit(struct amdxdna_client *client, u32 opcode,
		       u32 cmd_bo_hdl, u32 *arg_bo_hdls, u32 arg_bo_cnt,
		       u32 hwctx_hdl, u64 *seq)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_sched_job *job;
	struct amdxdna_hwctx *hwctx;
	int ret, idx;

	XDNA_DBG(xdna, "Command BO hdl %d, Arg BO count %d", cmd_bo_hdl, arg_bo_cnt);
	job = kzalloc(struct_size(job, bos, arg_bo_cnt), GFP_KERNEL);
	if (!job)
		return -ENOMEM;

	if (cmd_bo_hdl != AMDXDNA_INVALID_BO_HANDLE) {
		job->cmd_bo = amdxdna_gem_get_obj(client, cmd_bo_hdl, AMDXDNA_BO_CMD);
		if (!job->cmd_bo) {
			XDNA_ERR(xdna, "Failed to get cmd bo from %d", cmd_bo_hdl);
			ret = -EINVAL;
			goto free_job;
		}
	} else {
		job->cmd_bo = NULL;
		drm_WARN_ON(&xdna->ddev, opcode == OP_USER);
	}

	ret = amdxdna_arg_bos_lookup(client, job, arg_bo_hdls, arg_bo_cnt);
	if (ret) {
		XDNA_ERR(xdna, "Argument BOs lookup failed, ret %d", ret);
		goto cmd_put;
	}

	idx = srcu_read_lock(&client->hwctx_srcu);
	hwctx = idr_find(&client->hwctx_idr, hwctx_hdl);
	if (!hwctx) {
		XDNA_DBG(xdna, "PID %d failed to get hwctx %d",
			 client->pid, hwctx_hdl);
		ret = -EINVAL;
		goto unlock_srcu;
	}

	if (hwctx->status != HWCTX_STAT_READY) {
		XDNA_ERR(xdna, "HW Context is not ready");
		ret = -EINVAL;
		goto unlock_srcu;
	}

	job->hwctx = hwctx;
	job->mm = current->mm;
	job->opcode = opcode;

	job->fence = amdxdna_fence_create(hwctx);
	if (!job->fence) {
		XDNA_ERR(xdna, "Failed to create fence");
		ret = -ENOMEM;
		goto unlock_srcu;
	}
	kref_init(&job->refcnt);

	ret = xdna->dev_info->ops->cmd_submit(hwctx, job, seq);
	if (ret)
		goto put_fence;

	/*
	 * The amdxdna_hwctx_destroy_rcu() will release hwctx and associated
	 * resource after synchronize_srcu(). The submitted jobs should be
	 * handled by the queue, for example DRM scheduler, in device layer.
	 * For here we can unlock SRCU.
	 */
	srcu_read_unlock(&client->hwctx_srcu, idx);
	trace_amdxdna_debug_point(hwctx->name, *seq, "job pushed");

	return 0;

put_fence:
	dma_fence_put(job->fence);
unlock_srcu:
	srcu_read_unlock(&client->hwctx_srcu, idx);
	amdxdna_arg_bos_put(job);
cmd_put:
	amdxdna_gem_put_obj(job->cmd_bo);
free_job:
	kfree(job);
	return ret;
}

/*
 * The submit command ioctl submits a command to firmware. One firmware command
 * may contain multiple command BOs for processing as a whole.
 * The command sequence number is returned which can be used for wait command ioctl.
 */
static int amdxdna_drm_submit_execbuf(struct amdxdna_client *client,
				      struct amdxdna_drm_exec_cmd *args)
{
	struct amdxdna_dev *xdna = client->xdna;
	u32 *arg_bo_hdls;
	u32 cmd_bo_hdl;
	int ret;

	if (!args->arg_count || args->arg_count > MAX_ARG_COUNT) {
		XDNA_ERR(xdna, "Invalid arg bo count %d", args->arg_count);
		return -EINVAL;
	}

	/* Only support single command for now. */
	if (args->cmd_count != 1) {
		XDNA_ERR(xdna, "Invalid cmd bo count %d", args->cmd_count);
		return -EINVAL;
	}

	cmd_bo_hdl = (u32)args->cmd_handles;
	arg_bo_hdls = kcalloc(args->arg_count, sizeof(u32), GFP_KERNEL);
	if (!arg_bo_hdls)
		return -ENOMEM;
	ret = copy_from_user(arg_bo_hdls, u64_to_user_ptr(args->args),
			     args->arg_count * sizeof(u32));
	if (ret) {
		ret = -EFAULT;
		goto free_cmd_bo_hdls;
	}

	ret = amdxdna_cmd_submit(client, OP_USER, cmd_bo_hdl, arg_bo_hdls,
				 args->arg_count, args->hwctx, &args->seq);
	if (ret)
		XDNA_DBG(xdna, "Submit cmds failed, ret %d", ret);

free_cmd_bo_hdls:
	kfree(arg_bo_hdls);
	if (!ret)
		XDNA_DBG(xdna, "Pushed cmd %lld to scheduler", args->seq);
	return ret;
}

int amdxdna_drm_submit_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_drm_exec_cmd *args = data;

	if (args->ext_flags)
		return -EINVAL;

	switch (args->type) {
	case AMDXDNA_CMD_SUBMIT_EXEC_BUF:
		return amdxdna_drm_submit_execbuf(client, args);
	}

	XDNA_ERR(client->xdna, "Invalid command type %d", args->type);
	return -EINVAL;
}

int amdxdna_cmd_wait(struct amdxdna_client *client, u32 hwctx_hdl,
		     u64 seq, u32 timeout)
{
	struct amdxdna_dev *xdna = client->xdna;
	struct amdxdna_hwctx *hwctx;
	int ret, idx;

	if (!xdna->dev_info->ops->cmd_wait)
		return -EOPNOTSUPP;

	/* For locking concerns, see amdxdna_drm_exec_cmd_ioctl. */
	idx = srcu_read_lock(&client->hwctx_srcu);
	hwctx = idr_find(&client->hwctx_idr, hwctx_hdl);
	if (!hwctx) {
		XDNA_DBG(xdna, "PID %d failed to get hwctx %d",
			 client->pid, hwctx_hdl);
		ret = -EINVAL;
		goto unlock_hwctx_srcu;
	}

	ret = xdna->dev_info->ops->cmd_wait(hwctx, seq, timeout);

unlock_hwctx_srcu:
	srcu_read_unlock(&client->hwctx_srcu, idx);
	return ret;
}

int amdxdna_drm_wait_cmd_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	struct amdxdna_client *client = filp->driver_priv;
	struct amdxdna_dev *xdna = to_xdna_dev(dev);
	struct amdxdna_drm_wait_cmd *args = data;
	int ret;

	XDNA_DBG(xdna, "PID %d hwctx %d timeout set %d ms for cmd %lld",
		 client->pid, args->hwctx, args->timeout, args->seq);

	ret = amdxdna_cmd_wait(client, args->hwctx, args->seq, args->timeout);

	XDNA_DBG(xdna, "PID %d hwctx %d cmd %lld wait finished, ret %d",
		 client->pid, args->hwctx, args->seq, ret);

	return ret;
}
