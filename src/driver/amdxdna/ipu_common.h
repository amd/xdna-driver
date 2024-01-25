/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2022-2024 Advanced Micro Devices, Inc.
 */

#ifndef __IPU_COMMON_H__
#define __IPU_COMMON_H__

#include <linux/iopoll.h>
#include "drm_local/amdxdna_accel.h"
#include "amdxdna_drv.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_psp.h"

#define IPU_INTERVAL	20000	/* us */
#define IPU_TIMEOUT	1000000	/* us */

#define IDEV2PDEV(idev) \
	((idev)->xdna->pdev)

#define IPU_SRAM_OFF(idev, addr) \
	((addr) - (idev)->priv->sram_dev_addr)
#define IPU_MBOX_OFF(idev, addr) \
	((addr) - (idev)->priv->mbox_dev_addr)

#define PSP_REG_BAR(idev, idx) \
	((idev)->priv->psp_regs_off[(idx)].bar_idx)
#define PSP_REG_OFF(idev, idx) \
	((idev)->priv->psp_regs_off[(idx)].offset)
#define SRAM_REG_OFF(idev, idx) \
	((idev)->priv->sram_offs[(idx)].offset)

#define SMU_REG(idev, idx) \
({ \
	typeof(idev) _idev = idev; \
	((_idev)->smu_base + (_idev)->priv->smu_regs_off[(idx)].offset); \
})
#define SRAM_GET_ADDR(idev, idx) \
({ \
	typeof(idev) _idev = idev; \
	((_idev)->sram_base + SRAM_REG_OFF((_idev), (idx))); \
})

/* Firmware determines device memory base address and size */
#define IPU_DEVM_BASE	0x4000000
#define IPU_DEVM_SIZE	(48 * 1024 * 1024)

#define CHAN_SLOT_SZ 0x2000
#define CHANN_INDEX(idev, rbuf_off) \
	(((rbuf_off) - SRAM_REG_OFF((idev), MBOX_CHANN_OFF)) / CHAN_SLOT_SZ)

#define MBOX_SIZE(idev) \
({ \
	typeof(idev) _idev = (idev); \
	((_idev)->priv->mbox_size) ? (_idev)->priv->mbox_size : \
	pci_resource_len(IDEV2PDEV(_idev), (_idev)->xdna->dev_info->mbox_bar); \
})

/*
 * Highlight device specific macro naming rules:
 * 1. All of device specific macros should use prefix "<device name>_"
 * 2. Name PSP/SMU/SRAM related addresses as "<device name>_<enum name>_ADDR"
 *    a. Adding a new device, copy existed macro and update <device name> ;)
 * 3. Name REG/MBOX/PSP/SMU/SRAM BAR macros like "<device name>_<bar>_BAR_*"
 *
 * Examples for Phoenix device (see ipu_phx_regs.c):
 * 1. Define REG BAR info:
 * #define PHX_REG_BAR_INDEX <index>
 * #define PHX_REG_BAR_BASE  <address>
 *
 * 2. Define PSP_CMD_REG on PSP BAR:
 * #define PHX_REG_PSP_CMD_REG_ADDR <address>
 *
 * Please follow above naming rules, then use BAR_OFFSET_PAIR, _BAR_IDX,
 * _BAR_BASE, *_OFFSETS macros to create device info struct.
 */

/* device_bar name, enum name */
#define BAR_OFFSET_PAIR(d_b, e) \
{ \
	d_b##_BAR_INDEX, \
	d_b##_##e##_ADDR - d_b##_BAR_BASE, \
}

#define _BAR_IDX(_dev, bar) _dev##bar##_BAR_INDEX
#define _BAR_BASE(_dev, bar) _dev##bar##_BAR_BASE

#define DEFAULT_PSP_OFFSETS(_dev, empty...) \
{ \
	BAR_OFFSET_PAIR(_dev##PSP, PSP_CMD_REG), \
	BAR_OFFSET_PAIR(_dev##PSP, PSP_ARG0_REG), \
	BAR_OFFSET_PAIR(_dev##PSP, PSP_ARG1_REG), \
	BAR_OFFSET_PAIR(_dev##PSP, PSP_ARG2_REG), \
	BAR_OFFSET_PAIR(_dev##PSP, PSP_INTR_REG), \
	BAR_OFFSET_PAIR(_dev##PSP, PSP_STATUS_REG), \
	BAR_OFFSET_PAIR(_dev##PSP, PSP_RESP_REG), \
}

#define DEFAULT_SMU_OFFSETS(_dev, empty...) \
{ \
	BAR_OFFSET_PAIR(_dev##SMU, SMU_CMD_REG), \
	BAR_OFFSET_PAIR(_dev##SMU, SMU_ARG_REG), \
	BAR_OFFSET_PAIR(_dev##SMU, SMU_INTR_REG), \
	BAR_OFFSET_PAIR(_dev##SMU, SMU_RESP_REG), \
	BAR_OFFSET_PAIR(_dev##SMU, SMU_OUT_REG), \
}

#define DEFAULT_SRAM_OFFSETS(_dev, empty...) \
{ \
	BAR_OFFSET_PAIR(_dev##SRAM, MBOX_CHANN_OFF), \
	BAR_OFFSET_PAIR(_dev##SRAM, FW_ALIVE_OFF), \
}

#define _DEFINE_DEV_INFO(name, _vbnv, id, _sram, _psp, _smu, _fw_path, \
			 _fw_hash_high, _fw_hash_low) \
struct amdxdna_dev_info ipu_##id##_info = { \
	.reg_bar  = _BAR_IDX(name##_, REG), \
	.mbox_bar = _BAR_IDX(name##_, MBOX), \
	.sram_bar = _BAR_IDX(name##_, SRAM), \
	.psp_bar  = _BAR_IDX(name##_, PSP), \
	.smu_bar  = _BAR_IDX(name##_, SMU), \
	.dev_mem_base = IPU_DEVM_BASE, \
	.dev_mem_size = IPU_DEVM_SIZE, \
	.vbnv	  = _vbnv, \
	.device_type = AMDXDNA_DEV_TYPE_IPU, \
	.dev_priv = (&(struct ipu_dev_priv) { \
		.fw_path = _fw_path, \
		.fw_hash_high = _fw_hash_high, \
		.fw_hash_low = _fw_hash_low, \
		.mbox_dev_addr = _BAR_BASE(name##_, MBOX), \
		.mbox_size = 0, \
		.sram_dev_addr = _BAR_BASE(name##_, SRAM), \
		.sram_offs    = _sram(name##_), \
		.psp_regs_off = _psp(name##_), \
		.smu_regs_off = _smu(name##_), \
	}), \
}

#define IPU_DEFINE_DEV_INFO(name, _vbnv, id, fw_path, fw_hash_high, fw_hash_low) \
	_DEFINE_DEV_INFO(name, _vbnv, id, DEFAULT_SRAM_OFFSETS, \
			 DEFAULT_PSP_OFFSETS, DEFAULT_SMU_OFFSETS, \
			 fw_path, fw_hash_high, fw_hash_low)

#define IPU_DEFINE_DEV_INFO_PSP(name, _vbnv, id, _psp, fw_path, \
				fw_hash_high, fw_hash_low) \
	_DEFINE_DEV_INFO(name, _vbnv, id, DEFAULT_SRAM_OFFSETS, \
			 _psp, DEFAULT_SMU_OFFSETS, fw_path, fw_hash_high, fw_hash_low)

enum ipu_smu_reg_idx {
	SMU_CMD_REG = 0,
	SMU_ARG_REG,
	SMU_INTR_REG,
	SMU_RESP_REG,
	SMU_OUT_REG,
	SMU_MAX_REGS /* Kepp this at the end */
};

enum ipu_sram_reg_idx {
	MBOX_CHANN_OFF = 0,
	FW_ALIVE_OFF,
	SRAM_MAX_INDEX /* Keep this at the end */
};

struct ipu_bar_off_pair {
	int	bar_idx;
	u32	offset;
};

struct ipu_dev_priv {
	const char		*fw_path;
	u64			fw_hash_high;
	u64			fw_hash_low;
	u32			mbox_dev_addr;
	/* If mbox_size is 0, use BAR size. See MBOX_SIZE macro */
	u32			mbox_size;
	u32			sram_dev_addr;
	struct ipu_bar_off_pair	sram_offs[SRAM_MAX_INDEX];
	struct ipu_bar_off_pair	psp_regs_off[PSP_MAX_REGS];
	struct ipu_bar_off_pair	smu_regs_off[SMU_MAX_REGS];
};

struct aie_version {
	struct sysfs_mgr_node node;
	u16 major;
	u16 minor;
};

struct aie_tile_metadata {
	struct sysfs_mgr_node node;
	u16 row_count;
	u16 row_start;
	u16 dma_channel_count;
	u16 lock_count;
	u16 event_reg_count;
};

struct aie_metadata {
	struct sysfs_mgr_node node;
	u32 size;
	u16 cols;
	u16 rows;
	struct aie_version version;
	struct aie_tile_metadata core;
	struct aie_tile_metadata mem;
	struct aie_tile_metadata shim;
};

struct clock_entry {
	struct sysfs_mgr_node node;
	char name[16];
	u32 freq_mhz;
};

struct ipu_device {
	struct amdxdna_dev		*xdna;
	const struct ipu_dev_priv	*priv;
	void			__iomem *sram_base;
	void			__iomem *smu_base;
	struct psp_device		*psp_hdl;
	void				*xrs_hdl;

	struct xdna_mailbox_chann_res	mgmt_x2i;
	struct xdna_mailbox_chann_res	mgmt_i2x;
	u32				mgmt_chan_idx;

	struct sysfs_mgr_node		aie_dir;
	struct aie_version		version;
	struct aie_metadata		metadata;

	struct sysfs_mgr_node		clocks_dir;
	struct clock_entry		mp_ipu_clock;
	struct clock_entry		h_clock;
};

/* ipu_debugfs.c */
void ipu_debugfs_init(struct ipu_device *idev);

/* ipu_smu.c */
int ipu_smu_init(struct ipu_device *idev);
void ipu_smu_fini(struct ipu_device *idev);
int ipu_smu_set_mpipu_clock_freq(struct ipu_device *idev, u32 freq_mhz);
int ipu_smu_set_hclock_freq(struct ipu_device *idev, u32 freq_mhz);
int ipu_smu_set_power_on(struct ipu_device *idev);
int ipu_smu_set_power_off(struct ipu_device *idev);

#endif /* __IPU_COMMON_H__ */
