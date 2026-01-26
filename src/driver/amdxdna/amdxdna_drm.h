/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_DRM_H_
#define _AMDXDNA_DRM_H_

#include <linux/srcu.h>
#include <drm/drm_drv.h>
#include <drm/drm_print.h>
#include <drm/drm_file.h>
#include <linux/hmm.h>
#include <linux/iova.h>
#include <linux/timekeeping.h>
#include <linux/workqueue.h>
#include <linux/seqlock_types.h>

#include "amdxdna_ctx.h"
#include "amdxdna_dpt.h"
#include "amdxdna_gem.h"

#define MAX_MEM_REGIONS	16

#define XDNA_INFO(xdna, fmt, args...)	dev_info((xdna)->ddev.dev, fmt, ##args)
#define XDNA_WARN(xdna, fmt, args...) \
	dev_warn((xdna)->ddev.dev, "%s: " fmt, __func__, ##args)
#define XDNA_ERR(xdna, fmt, args...) \
	dev_err_ratelimited((xdna)->ddev.dev, "%s: " fmt, __func__, ##args)
#define XDNA_DBG(xdna, fmt, args...)	dev_dbg((xdna)->ddev.dev, fmt, ##args)

#define XDNA_INFO_ONCE(xdna, fmt, args...)	dev_info_once((xdna)->ddev.dev, fmt, ##args)

#define to_xdna_dev(drm_dev) \
	((struct amdxdna_dev *)container_of(drm_dev, struct amdxdna_dev, ddev))

extern const struct drm_driver amdxdna_drm_drv;

struct amdxdna_dev;
struct amdxdna_client;
struct amdxdna_dev_hdl;
struct amdxdna_dev_priv;
struct amdxdna_mgmt_dma_hdl;

/*
 * struct amdxdna_dev_ops - Device hardware operation callbacks
 */
struct amdxdna_dev_ops {
	int (*init)(struct amdxdna_dev *xdna);
	void (*fini)(struct amdxdna_dev *xdna);
	int (*get_dev_revision)(struct amdxdna_dev *xdna, u32 *rev);
	void (*tdr_start)(struct amdxdna_dev *xdna);
	void (*tdr_stop)(struct amdxdna_dev *xdna);
	int (*resume)(struct amdxdna_dev *xdna);
	void (*suspend)(struct amdxdna_dev *xdna);
	void (*reset_prepare)(struct amdxdna_dev *xdna);
	int (*reset_done)(struct amdxdna_dev *xdna);
	int (*sriov_configure)(struct amdxdna_dev *xdna, int num_vfs);
	int (*mmap)(struct amdxdna_dev *xdna, struct vm_area_struct *vma);
	void (*debugfs)(struct amdxdna_dev *xdna);
	int (*fw_log_init)(struct amdxdna_dev *xdna, size_t size, u8 level);
	int (*fw_log_config)(struct amdxdna_dev *xdna, u8 level);
	int (*fw_log_fini)(struct amdxdna_dev *xdna);
	void (*fw_log_parse)(struct amdxdna_dev *xdna, char *buffer, size_t size);
	int (*fw_trace_init)(struct amdxdna_dev *xdna, size_t size, u32 categories);
	int (*fw_trace_config)(struct amdxdna_dev *xdna, u32 categories);
	int (*fw_trace_fini)(struct amdxdna_dev *xdna);
	void (*fw_trace_parse)(struct amdxdna_dev *xdna, char *buffer, size_t size);

	/* Below device ops are called by IOCTL */
	int (*ctx_init)(struct amdxdna_ctx *ctx);
	void (*ctx_fini)(struct amdxdna_ctx *ctx);
	int (*ctx_config)(struct amdxdna_ctx *ctx, u32 type, u64 value, void *buf, u32 size);
	void (*hmm_invalidate)(struct amdxdna_gem_obj *abo, unsigned long cur_seq);
	int (*cmd_submit)(struct amdxdna_sched_job *job,
			  u32 *syncobj_hdls, u64 *syncobj_points, u32 syncobj_cnt, u64 *seq);
	int (*cmd_wait)(struct amdxdna_ctx *ctx, u64 seq, u32 timeout);
	int (*get_aie_info)(struct amdxdna_client *client, struct amdxdna_drm_get_info *args);
	int (*get_aie_array)(struct amdxdna_client *client, struct amdxdna_drm_get_array *args);
	int (*set_aie_state)(struct amdxdna_client *client, struct amdxdna_drm_set_state *args);
	struct dma_fence *(*cmd_get_out_fence)(struct amdxdna_ctx *ctx, u64 seq);
};

/* Revision to VBNV string mapping table entry */
struct amdxdna_rev_vbnv {
	u32		revision;
	const char	*vbnv;
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
 * @doorbell_bar: Index of DOORBELL BAR
 * @device_type: type of the device
 * @first_col: First column for application
 * @dev_mem_buf_shift: heap buffer alignment shift
 * @dev_mem_base: Base address of device heap memory
 * @dev_mem_size: Size of device heap memory
 * @default_vbnv: Default board name based on PCIe device ID. Different boards
 *                may share the same PCIe device ID, so this may not accurately
 *                identify the board. Used as fallback when firmware query fails.
 * @rev_vbnv_tbl: Table mapping device revision to VBNV string (NULL terminated)
 * @dev_priv: Device private data
 * @ops: Device operations callback
 */
struct amdxdna_dev_info {
	int				reg_bar;
	int				mbox_bar;
	int				sram_bar;
	int				psp_bar;
	int				smu_bar;
	int				doorbell_bar;
	int				device_type;
	int				first_col;
	u32				dev_mem_buf_shift;
	u64				dev_mem_base;
	size_t				dev_mem_size;
	char				*default_vbnv;
	const struct amdxdna_rev_vbnv	*rev_vbnv_tbl;
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

	/* Accurate board name queried from firmware, or default_vbnv as fallback */
	const char			*vbnv;

	/* This protects client list */
	struct mutex			dev_lock;
	struct list_head		client_list;
	struct amdxdna_fw_ver		fw_ver;
	struct amdxdna_dpt		*fw_log;
	struct amdxdna_dpt		*fw_trace;
#ifdef AMDXDNA_DEVEL
	struct ida			pdi_ida;
#endif
	struct rw_semaphore		notifier_lock; /* for mmu notifier */
	struct workqueue_struct		*notifier_wq;

	struct device			*cma_region_devs[MAX_MEM_REGIONS];

	struct iommu_group		*group;
	struct iommu_domain		*domain;
	struct iova_domain		iovad;
};

struct amdxdna_stats {
	seqlock_t			lock; /* protect stats */
	int				job_depth;
	ktime_t				start_time;
	u64				busy_time;
};

/*
 * struct amdxdna_client - amdxdna client
 * A per fd data structure for managing context and other user process stuffs.
 *
 * @node: entry node in clients list
 * @pid: PID of current client
 * @ctx_srcu: Per client SRCU for synchronizing ctx destroy with other ioctls.
 * @ctx_xa: context xarray
 * @xdna: XDNA device pointer
 * @filp: DRM file pointer
 * @mm_lock: lock for client wide memory related
 * @dev_heap: Shared device heap memory
 * @heap_usage: Total number of bytes allocated in heap memory
 * @sva: iommu SVA handle
 * @pasid: PASID
 * @stats: record npu usage stats
 */
struct amdxdna_client {
	struct list_head		node;
	pid_t				pid;
	kuid_t				uid;
	/* To avoid deadlock, do NOT wait this srcu when dev_lock is hold */
	struct srcu_struct		ctx_srcu;
	struct xarray			ctx_xa;
	u32				next_ctxid;
	struct amdxdna_dev		*xdna;
	struct drm_file			*filp;

	struct mutex			mm_lock; /* protect memory related */
	struct amdxdna_gem_obj		*dev_heap;
	u32				heap_usage;
	size_t				total_bo_usage;
	size_t				total_int_bo_usage;

	struct iommu_sva		*sva;
	int				pasid;

	struct amdxdna_stats		stats;
};

#define amdxdna_for_each_ctx(client, ctx_id, entry)		\
	xa_for_each(&(client)->ctx_xa, ctx_id, entry)
#define amdxdna_no_ctx(client)				\
	xa_empty(&(client)->ctx_xa)

void amdxdna_stats_start(struct amdxdna_client *client);
void amdxdna_stats_account(struct amdxdna_client *client);
int amdxdna_drm_copy_array_to_user(struct amdxdna_drm_get_array *tgt,
				   void *array, size_t element_size, size_t num_element);
int amdxdna_drm_copy_array_from_user(struct amdxdna_drm_get_array *src,
				     void *array, size_t element_size, size_t num_element);
bool amdxdna_admin_access_allowed(struct amdxdna_dev *xdna);
bool amdxdna_ctx_access_allowed(struct amdxdna_ctx *ctx, bool root_only);

int amdxdna_iommu_init(struct amdxdna_dev *xdna);
void amdxdna_iommu_fini(struct amdxdna_dev *xdna);
int amdxdna_iommu_map_bo(struct amdxdna_dev *xdna, struct amdxdna_gem_obj *abo);
void amdxdna_iommu_unmap_bo(struct amdxdna_dev *xdna, struct amdxdna_gem_obj *abo);
void *amdxdna_iommu_alloc(struct amdxdna_dev *xdna, size_t size, dma_addr_t *dma_addr);
void amdxdna_iommu_free(struct amdxdna_dev *xdna, size_t size,
			void *cpu_addr, dma_addr_t dma_addr);
static inline bool amdxdna_iova_enabled(struct amdxdna_dev *xdna)
{
	return !!xdna->domain;
}

#endif /* _AMDXDNA_DRM_H_ */
