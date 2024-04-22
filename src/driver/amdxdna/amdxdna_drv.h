/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_DRV_H_
#define _AMDXDNA_DRV_H_

#include <linux/pci.h>
#include <linux/srcu.h>
#include <linux/uuid.h>
#include <drm/drm_drv.h>
#include <drm/drm_print.h>
#include <drm/drm_file.h>

#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"

#define AMDXDNA_DRIVER_NAME "amdxdna"

#define XDNA_INFO(xdna, fmt, args...)	dev_info((xdna)->ddev.dev, fmt, ##args)
#define XDNA_WARN(xdna, fmt, args...)	dev_warn((xdna)->ddev.dev, "%s: "fmt, __func__, ##args)
#define XDNA_ERR(xdna, fmt, args...)	dev_err((xdna)->ddev.dev, "%s: "fmt, __func__, ##args)
#define XDNA_DBG(xdna, fmt, args...)	dev_dbg((xdna)->ddev.dev, fmt, ##args)

#define to_xdna_dev(drm_dev) \
	((struct amdxdna_dev *)container_of(drm_dev, struct amdxdna_dev, ddev))

struct amdxdna_dev;
struct npu_device;
struct npu_dev_priv;

/*
 * struct amdxdna_dev_ops - Device hardware operation callbacks
 *
 */
struct amdxdna_dev_ops {
	int (*init)(struct amdxdna_dev *xdna);
	void (*fini)(struct amdxdna_dev *xdna);
	int (*resume)(struct amdxdna_dev *xdna);
	void (*suspend)(struct amdxdna_dev *xdna);
	int (*get_info)(struct amdxdna_dev *xdna, struct amdxdna_drm_get_info *args);
	int (*set_state)(struct amdxdna_dev *xdna, struct amdxdna_drm_set_state *args);
	int (*mmap)(struct amdxdna_dev *xdna, struct vm_area_struct *vma);
	void (*debugfs)(struct amdxdna_dev *xdna);

	int (*hwctx_init)(struct amdxdna_hwctx *hwctx);
	void (*hwctx_fini)(struct amdxdna_hwctx *hwctx);
	int (*hwctx_config)(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size);
	void (*hwctx_suspend)(struct amdxdna_hwctx *hwctx);
	void (*hwctx_resume)(struct amdxdna_hwctx *hwctx);
	int (*cmd_submit)(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq);
	int (*cmd_wait)(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout);
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
	const struct npu_dev_priv	*dev_priv;
	const struct amdxdna_dev_ops	*ops;
};

/*
 * struct amdxdna_device_id - PCI device info
 *
 * @device: PCI device id
 * @revision: PCI revision id
 * @dev_info: device hardware information
 */
struct amdxdna_device_id {
	unsigned short device;
	u8 revision;
	const struct amdxdna_dev_info *dev_info;
};

struct amdxdna_fw_ver {
	u32 major;
	u32 minor;
	u32 sub;
	u32 build;
};

struct amdxdna_dev {
	struct drm_device		ddev;
	struct npu_device		*dev_handle;
	const struct amdxdna_dev_info	*dev_info;
	void				*xrs_hdl;

	struct mutex			dev_lock; /* protect client list, dev_info->ops, xrt_hdl */
	struct list_head		client_list;
	struct amdxdna_fw_ver		fw_ver;
};

/*
 * struct amdxdna_client - amdxdna client
 * A per fd data structure for managing context and other user process stuffs.
 *
 * @node: entry node in clients list
 * @pid: PID of current client
 * @hwctx_lock: HW context lock for protect IDR
 * @hwctx_srcu: Per client SRCU for synchronizing hwctx destroy with other ioctls.
 * @hwctx_idr: HW context IDR
 * @xdna: XDNA device pointer
 * @filp: DRM file pointer
 * @mm_lock: lock for client wide memory related
 * @dev_heap: Shared device heap memory
 * @client_sva: iommu SVA handle
 * @client_pasid: PASID
 */
struct amdxdna_client {
	struct list_head		node;
	pid_t				pid;
	/* To protect hwctx_idr and exclusion of hwctx stop/restart/destroy etc. */
	struct mutex			hwctx_lock;
	/* To avoid deadlock, do NOT wait this srcu when hwctx_lock is hold */
	struct srcu_struct		hwctx_srcu;
	struct idr			hwctx_idr;
	struct amdxdna_dev		*xdna;
	struct drm_file			*filp;

	spinlock_t			mm_lock; /* protect memory related */
	int				dev_heap;

	struct iommu_sva		*sva;
	int				pasid;
};

/* Add device info below */
extern const struct amdxdna_dev_info dev_npu1_info;
extern const struct amdxdna_dev_info dev_npu2_info;
extern const struct amdxdna_dev_info dev_npu4_info;

#endif /* _AMDXDNA_DRV_H_ */
