/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_DRV_H_
#define _AMDXDNA_DRV_H_

#include <drm/drm_device.h>
#include <drm/drm_print.h>
#include <linux/iommu.h>
#include <linux/iova.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>

#define XDNA_INFO(xdna, fmt, args...)	drm_info(&(xdna)->ddev, fmt, ##args)
#define XDNA_WARN(xdna, fmt, args...)	drm_warn(&(xdna)->ddev, "%s: "fmt, __func__, ##args)
#define XDNA_ERR(xdna, fmt, args...)	drm_err(&(xdna)->ddev, "%s: "fmt, __func__, ##args)
#define XDNA_DBG(xdna, fmt, args...)	drm_dbg(&(xdna)->ddev, fmt, ##args)
#define XDNA_INFO_ONCE(xdna, fmt, args...) drm_info_once(&(xdna)->ddev, fmt, ##args)

#define XDNA_MBZ_DBG(xdna, ptr, sz)					\
	({								\
		int __i;						\
		int __ret = 0;						\
		u8 *__ptr = (u8 *)(ptr);				\
		for (__i = 0; __i < (sz); __i++) {			\
			if (__ptr[__i]) {				\
				XDNA_DBG(xdna, "MBZ check failed");	\
				__ret = -EINVAL;			\
				break;					\
			}						\
		}							\
		__ret;							\
	})

#define to_xdna_dev(drm_dev) \
	((struct amdxdna_dev *)container_of(drm_dev, struct amdxdna_dev, ddev))

extern const struct drm_driver amdxdna_drm_drv;

struct amdxdna_client;
struct amdxdna_dev;
struct amdxdna_dev_info;
struct amdxdna_drm_get_info;
struct amdxdna_drm_set_state;
struct amdxdna_drm_get_array;
struct amdxdna_gem_obj;
struct amdxdna_hwctx;
struct amdxdna_sched_job;

/*
 * 0.0: Initial version
 * 0.1: Support getting all hardware contexts by DRM_IOCTL_AMDXDNA_GET_ARRAY
 * 0.2: Support getting last error hardware error
 * 0.3: Support firmware debug buffer
 * 0.4: Support getting resource information
 * 0.5: Support getting telemetry data
 * 0.6: Support preemption
 */
#define AMDXDNA_DRIVER_MAJOR            0
#define AMDXDNA_DRIVER_MINOR            6

#define AMDXDNA_MODULE_LICENSE		"GPL"
#define AMDXDNA_MODULE_AUTHOR		"XRT Team <runtimeca39d@amd.com>"
#define AMDXDNA_MODULE_VERSION		"0.1"
#define AMDXDNA_MODULE_DESCRIPTION	"amdxdna driver"

/*
 * struct amdxdna_dev_ops - Device hardware operation callbacks
 */
struct amdxdna_dev_ops {
	int (*init)(struct amdxdna_dev *xdna);
	void (*fini)(struct amdxdna_dev *xdna);
	int (*resume)(struct amdxdna_dev *xdna);
	int (*suspend)(struct amdxdna_dev *xdna);
	int (*sriov_configure)(struct amdxdna_dev *xdna, int num_vfs);
	const struct drm_sched_backend_ops *sched_ops;
	int (*hwctx_init)(struct amdxdna_hwctx *hwctx);
	void (*hwctx_fini)(struct amdxdna_hwctx *hwctx);
	int (*hwctx_config)(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size);
	int (*hwctx_sync_debug_bo)(struct amdxdna_hwctx *hwctx, u32 debug_bo_hdl);
	void (*hmm_invalidate)(struct amdxdna_gem_obj *abo, unsigned long cur_seq);
	int (*cmd_submit)(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq);
	int (*get_aie_info)(struct amdxdna_client *client, struct amdxdna_drm_get_info *args);
	int (*set_aie_state)(struct amdxdna_client *client, struct amdxdna_drm_set_state *args);
	int (*get_array)(struct amdxdna_client *client, struct amdxdna_drm_get_array *args);
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

	struct mutex			dev_lock; /* per device lock */
	struct list_head		client_list;
	struct amdxdna_fw_ver		fw_ver;
	struct rw_semaphore		notifier_lock; /* for mmu notifier*/
	struct workqueue_struct		*notifier_wq;

	struct iommu_group		*group;
	struct iommu_domain		*domain;
	struct iova_domain		iovad;
};

/*
 * struct amdxdna_device_id - device info
 */
struct amdxdna_device_id {
	unsigned short device;
	u8 revision;
	const struct amdxdna_dev_info *dev_info;
};

/*
 * struct amdxdna_client - amdxdna client
 * A per fd data structure for managing context and other user process stuffs.
 */
struct amdxdna_client {
	struct list_head		node;
	pid_t				pid;
	struct srcu_struct		hwctx_srcu;
	struct xarray			hwctx_xa;
	u32				next_hwctxid;
	struct amdxdna_dev		*xdna;
	struct drm_file			*filp;

	struct mutex			mm_lock; /* protect memory related */
	struct amdxdna_gem_obj		*dev_heap;

	struct iommu_sva		*sva;
	int				pasid;
	struct mm_struct		*mm;

	size_t				heap_usage;
	size_t				total_bo_usage;
	size_t				total_int_bo_usage;
};

#define amdxdna_for_each_hwctx(client, hwctx_id, entry)		\
	xa_for_each(&(client)->hwctx_xa, hwctx_id, entry)

#define amdxdna_for_each_client(xdna, client)			\
	list_for_each_entry(client, &(xdna)->client_list, node)

int amdxdna_sysfs_init(struct amdxdna_dev *xdna);
void amdxdna_sysfs_fini(struct amdxdna_dev *xdna);

/* Common device initialization and registration */
int amdxdna_dev_init(struct amdxdna_dev *xdna);
void amdxdna_dev_cleanup(struct amdxdna_dev *xdna);

/* IOMMU helper functions */
int amdxdna_iommu_init(struct amdxdna_dev *xdna);
void amdxdna_iommu_fini(struct amdxdna_dev *xdna);
int amdxdna_iommu_map_bo(struct amdxdna_dev *xdna, struct amdxdna_gem_obj *abo);
void amdxdna_iommu_unmap_bo(struct amdxdna_dev *xdna, struct amdxdna_gem_obj *abo);
void *amdxdna_iommu_alloc(struct amdxdna_dev *xdna, size_t size, dma_addr_t *dma_addr);
void amdxdna_iommu_free(struct amdxdna_dev *xdna, size_t size,
			void *cpu_addr, dma_addr_t dma_addr);

static inline bool amdxdna_iova_on(struct amdxdna_dev *xdna)
{
	return !!xdna->domain;
}

static inline bool amdxdna_pasid_on(struct amdxdna_client *client)
{
	return client->pasid != IOMMU_PASID_INVALID;
}

#endif /* _AMDXDNA_DRV_H_ */
