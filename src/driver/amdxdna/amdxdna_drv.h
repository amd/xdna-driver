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
#include "amdxdna_xclbin.h"
#include "xrs.h"

#define AMDXDNA_DRIVER_NAME "amdxdna"

#define XDNA_INFO(xdna, fmt, args...)	dev_info(&(xdna)->pdev->dev, fmt, ##args)
#define XDNA_WARN(xdna, fmt, args...)	dev_warn(&(xdna)->pdev->dev, "%s: "fmt, __func__, ##args)
#define XDNA_ERR(xdna, fmt, args...)	dev_err(&(xdna)->pdev->dev, "%s: "fmt, __func__, ##args)
#define XDNA_DBG(xdna, fmt, args...)	dev_dbg(&(xdna)->pdev->dev, fmt, ##args)

#define to_xdna_dev(drm_dev) \
	((struct amdxdna_dev *)container_of(drm_dev, struct amdxdna_dev, ddev))

#define DECLARE_DEV_INFO(id) \
	struct amdxdna_dev_info npu_##id##_info
#define DEV_INFO_TO_DATA(id) \
	((kernel_ulong_t)&npu_##id##_info)

struct npu_device;
struct npu_dev_priv;
struct mailbox;
struct mailbox_channel;

/*
 * struct amdxdna_dev_info - Device hardware information
 * Record device static information, like reg, mbox, PSP, SMU bar index,
 *
 * @reg_bar: Index of public register BAR
 * @mbox_bar: Index of mailbox register BAR
 * @sram_bar: Index of SRAM BAR
 * @psp_bar: Index of PSP BAR
 * @smu_bar: Index of SMU BAR
 * @dev_mem_base: Base address of device heap memory
 * @dev_mem_size: Size of device heap memory
 * @vbnv: the VBNV string
 * @device_type: type of the device
 * @dev_priv: Device private data
 */
struct amdxdna_dev_info {
	int				reg_bar;
	int				mbox_bar;
	int				sram_bar;
	int				psp_bar;
	int				smu_bar;
	u64				dev_mem_base;
	size_t				dev_mem_size;
	char				*vbnv;
	int				device_type;
	const struct npu_dev_priv	*dev_priv;
};

struct amdxdna_dev {
	struct drm_device	ddev;
	struct pci_dev		*pdev;
	struct amdxdna_dev_info	*dev_info;

	struct mutex		dev_lock; /* per device lock */
	struct list_head	client_list;
	struct list_head	xclbin_list;
	struct ida		pdi_ida;
	struct npu_device	*dev_handle;

	/* Mailbox and the management channel */
	struct mailbox		*mbox;
	struct mailbox_channel	*mgmt_chann;
	struct task_struct	*async_msgd;
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
 * @mm_lock: lock for client wide memory related
 * @dev_heap: Shared device heap memory
 * @shmem_list: SHMEM backed BO list
 * @resv: DMA resv object for SHMEM BOs
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

	struct mutex			mm_lock; /* protect memory related */
	int				dev_heap;
	struct list_head		shmem_list;

	/* A per client resv. The idea is that all the shmem bo obj shared this
	 * DMA resv. So that all SHMEM objects can be locked at once.
	 */
	struct dma_resv			resv;

	struct iommu_sva		*sva;
	int				pasid;
};

/* Add device info below */
extern const DECLARE_DEV_INFO(1502);
extern const DECLARE_DEV_INFO(17f0);

#endif /* _AMDXDNA_DRV_H_ */
