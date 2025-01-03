/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_DRM_H_
#define _AMDXDNA_DRM_H_

#include <linux/srcu.h>
#include <drm/drm_drv.h>
#include <drm/drm_print.h>
#include <drm/drm_file.h>
#include <linux/hmm.h>
#include <linux/timekeeping.h>
#include <linux/workqueue.h>

#include "amdxdna_ctx.h"
#ifdef AMDXDNA_SHMEM
#include "amdxdna_gem.h"
#else
#include "amdxdna_gem_dma.h"
#endif
#include "amdxdna_tdr.h"

#define XDNA_INFO(xdna, fmt, args...)	dev_info((xdna)->ddev.dev, fmt, ##args)
#define XDNA_WARN(xdna, fmt, args...)	dev_warn((xdna)->ddev.dev, "%s: "fmt, __func__, ##args)
#define XDNA_ERR(xdna, fmt, args...)	dev_err((xdna)->ddev.dev, "%s: "fmt, __func__, ##args)
#define XDNA_DBG(xdna, fmt, args...)	dev_dbg((xdna)->ddev.dev, fmt, ##args)

#define XDNA_INFO_ONCE(xdna, fmt, args...)	dev_info_once((xdna)->ddev.dev, fmt, ##args)

#define to_xdna_dev(drm_dev) \
	((struct amdxdna_dev *)container_of(drm_dev, struct amdxdna_dev, ddev))

#define tdr_to_xdna_dev(t) \
	((struct amdxdna_dev *)container_of(t, struct amdxdna_dev, tdr))

extern const struct drm_driver amdxdna_drm_drv;

struct amdxdna_dev;
struct amdxdna_client;
struct amdxdna_dev_hdl;
struct amdxdna_dev_priv;

/*
 * struct amdxdna_dev_ops - Device hardware operation callbacks
 */
struct amdxdna_dev_ops {
	int (*init)(struct amdxdna_dev *xdna);
	void (*fini)(struct amdxdna_dev *xdna);
	void (*recover)(struct amdxdna_dev *xdna, bool dump_only);
	int (*resume)(struct amdxdna_dev *xdna);
	void (*suspend)(struct amdxdna_dev *xdna);
	int (*mmap)(struct amdxdna_dev *xdna, struct vm_area_struct *vma);
	void (*debugfs)(struct amdxdna_dev *xdna);

	/* Below device ops are called by IOCTL */
	int (*hwctx_init)(struct amdxdna_hwctx *hwctx);
	void (*hwctx_fini)(struct amdxdna_hwctx *hwctx);
	void (*hwctx_free)(struct amdxdna_hwctx *hwctx);
	int (*hwctx_config)(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size);
	void (*hmm_invalidate)(struct amdxdna_gem_obj *abo, unsigned long cur_seq);
	void (*hwctx_suspend)(struct amdxdna_hwctx *hwctx);
	void (*hwctx_resume)(struct amdxdna_hwctx *hwctx);
	int (*cmd_submit)(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
			  u32 *syncobj_hdls, u64 *syncobj_points, u32 syncobj_cnt, u64 *seq);
	int (*cmd_wait)(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout);
	int (*get_aie_info)(struct amdxdna_client *client, struct amdxdna_drm_get_info *args);
	int (*set_aie_state)(struct amdxdna_client *client, struct amdxdna_drm_set_state *args);
	struct dma_fence *(*cmd_get_out_fence)(struct amdxdna_hwctx *hwctx, u64 seq);
};

/*
 * struct amdxdna_dev_info - Device hardware information
 * Record device static information, like reg, mbox, PSP, SMU bar index,
 *
 * @reg_bar: Index of public register BAR
 * @mbox_bar: Index of mailbox register BAR
 * @sram_bar: Index of SRAM BAR
 * @psp_bar: Index of PSP BAR
 * @smu_bar: Index of SMU BAR
 * @device_type: type of the device
 * @first_col: First column for application
 * @dev_mem_buf_shift: heap buffer alignment shift
 * @dev_mem_base: Base address of device heap memory
 * @dev_mem_size: Size of device heap memory
 * @vbnv: the VBNV string
 * @dev_priv: Device private data
 * @ops: Device operations callback
 */
struct amdxdna_dev_info {
	int				reg_bar;
	int				mbox_bar;
	int				sram_bar;
	int				psp_bar;
	int				smu_bar;
	int				device_type;
	int				first_col;
	u32				dev_mem_buf_shift;
	u64				dev_mem_base;
	size_t				dev_mem_size;
	char				*vbnv;
	const struct amdxdna_dev_priv	*dev_priv;
	const struct amdxdna_dev_ops	*ops;
};

struct amdxdna_fw_ver {
	u32 major;
	u32 minor;
	u32 sub;
	u32 build;
};

struct amdxdna_dev {
	struct drm_device		ddev;
	struct amdxdna_dev_hdl		*dev_handle;
	const struct amdxdna_dev_info	*dev_info;
	void				*xrs_hdl;

	struct mutex			dev_lock; /* protect client list, dev_info->ops, xrs_hdl */
	struct list_head		client_list;
	struct amdxdna_fw_ver		fw_ver;
	struct amdxdna_tdr		tdr;
#ifdef AMDXDNA_DEVEL
	struct ida			pdi_ida;
#endif
	struct rw_semaphore		notifier_lock; /* for mmu notifier*/
	struct workqueue_struct		*notifier_wq;
};

struct amdxdna_stats {
	spinlock_t			lock; /* protect stats */
	u32				job_depth;
	ktime_t				busy_time;
	ktime_t				start_time;
};

/*
 * struct amdxdna_client - amdxdna client
 * A per fd data structure for managing context and other user process stuffs.
 *
 * @node: entry node in clients list
 * @pid: PID of current client
 * @hwctx_lock: HW context lock for protect IDR
 * @hwctx_srcu: Per client SRCU for synchronizing hwctx destroy with other ioctls.
 * @hwctx_xa: HW context xarray
 * @xdna: XDNA device pointer
 * @filp: DRM file pointer
 * @mm_lock: lock for client wide memory related
 * @dev_heap: Shared device heap memory
 * @sva: iommu SVA handle
 * @pasid: PASID
 * @stats: record npu usage stats
 */
struct amdxdna_client {
	struct list_head		node;
	pid_t				pid;
	/* To protect hwctx stop/restart/destroy etc. */
	struct mutex			hwctx_lock;
	/* To avoid deadlock, do NOT wait this srcu when hwctx_lock is hold */
	struct srcu_struct		hwctx_srcu;
	struct xarray			hwctx_xa;
	u32				next_hwctxid;
	struct amdxdna_dev		*xdna;
	struct drm_file			*filp;

	struct mutex			mm_lock; /* protect memory related */
	struct amdxdna_gem_obj		*dev_heap;

	struct iommu_sva		*sva;
	int				pasid;

	struct amdxdna_stats		stats;
};

#define amdxdna_for_each_hwctx(client, hwctx_id, entry)		\
	xa_for_each(&(client)->hwctx_xa, hwctx_id, entry)
#define amdxdna_no_hwctx(client)				\
	xa_empty(&(client)->hwctx_xa)

void amdxdna_update_stats(struct amdxdna_client *client, ktime_t time, bool start);

#endif /* _AMDXDNA_DRM_H_ */
