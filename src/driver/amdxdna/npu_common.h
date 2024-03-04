/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef __NPU_COMMON_H__
#define __NPU_COMMON_H__

#include <linux/iopoll.h>
#include "drm_local/amdxdna_accel.h"
#include "amdxdna_drv.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_psp.h"

#define NPU_INTERVAL	20000	/* us */
#define NPU_TIMEOUT	1000000	/* us */

#define NDEV2PDEV(ndev) \
	((ndev)->xdna->pdev)

#define NPU_SRAM_OFF(ndev, addr) \
	((addr) - (ndev)->priv->sram_dev_addr)
#define NPU_MBOX_OFF(ndev, addr) \
	((addr) - (ndev)->priv->mbox_dev_addr)

#define PSP_REG_BAR(ndev, idx) \
	((ndev)->priv->psp_regs_off[(idx)].bar_idx)
#define PSP_REG_OFF(ndev, idx) \
	((ndev)->priv->psp_regs_off[(idx)].offset)
#define SRAM_REG_OFF(ndev, idx) \
	((ndev)->priv->sram_offs[(idx)].offset)

#define SMU_REG(ndev, idx) \
({ \
	typeof(ndev) _ndev = ndev; \
	((_ndev)->smu_base + (_ndev)->priv->smu_regs_off[(idx)].offset); \
})
#define SRAM_GET_ADDR(ndev, idx) \
({ \
	typeof(ndev) _ndev = ndev; \
	((_ndev)->sram_base + SRAM_REG_OFF((_ndev), (idx))); \
})

/* Firmware determines device memory base address and size */
#define NPU_DEVM_BASE	0x4000000
#define NPU_DEVM_SIZE	(48 * 1024 * 1024)

#define CHAN_SLOT_SZ 0x2000
#define CHANN_INDEX(ndev, rbuf_off) \
	(((rbuf_off) - SRAM_REG_OFF((ndev), MBOX_CHANN_OFF)) / CHAN_SLOT_SZ)

#define MBOX_SIZE(ndev) \
({ \
	typeof(ndev) _ndev = (ndev); \
	((_ndev)->priv->mbox_size) ? (_ndev)->priv->mbox_size : \
	pci_resource_len(NDEV2PDEV(_ndev), (_ndev)->xdna->dev_info->mbox_bar); \
})

/*
 * Highlight device specific macro naming rules:
 * 1. All of device specific macros should use prefix "<device name>_"
 * 2. Name PSP/SMU/SRAM related addresses as "<device name>_<enum name>_ADDR"
 *    a. Adding a new device, copy existed macro and update <device name> ;)
 * 3. Name REG/MBOX/PSP/SMU/SRAM BAR macros like "<device name>_<bar>_BAR_*"
 *
 * Examples for npu1 device (see npu1_regs.c):
 * 1. Define REG BAR info:
 * #define NPU1_REG_BAR_INDEX <index>
 * #define NPU1_REG_BAR_BASE  <address>
 *
 * 2. Define PSP_CMD_REG on PSP BAR:
 * #define NPU1_REG_PSP_CMD_REG_ADDR <address>
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
			 _protocol_major, _protocol_minor) \
struct amdxdna_dev_info npu_##id##_info = { \
	.reg_bar  = _BAR_IDX(name##_, REG), \
	.mbox_bar = _BAR_IDX(name##_, MBOX), \
	.sram_bar = _BAR_IDX(name##_, SRAM), \
	.psp_bar  = _BAR_IDX(name##_, PSP), \
	.smu_bar  = _BAR_IDX(name##_, SMU), \
	.dev_mem_base = NPU_DEVM_BASE, \
	.dev_mem_size = NPU_DEVM_SIZE, \
	.vbnv	  = _vbnv, \
	.device_type = AMDXDNA_DEV_TYPE_NPU, \
	.dev_priv = (&(struct npu_dev_priv) { \
		.fw_path = _fw_path, \
		.protocol_major = _protocol_major, \
		.protocol_minor = _protocol_minor, \
		.mbox_dev_addr = _BAR_BASE(name##_, MBOX), \
		.mbox_size = 0, \
		.sram_dev_addr = _BAR_BASE(name##_, SRAM), \
		.sram_offs    = _sram(name##_), \
		.psp_regs_off = _psp(name##_), \
		.smu_regs_off = _smu(name##_), \
	}), \
}

#define NPU_DEFINE_DEV_INFO(name, _vbnv, id, fw_path, protocol_major, protocol_minor) \
	_DEFINE_DEV_INFO(name, _vbnv, id, DEFAULT_SRAM_OFFSETS, \
			 DEFAULT_PSP_OFFSETS, DEFAULT_SMU_OFFSETS, \
			 fw_path, protocol_major, protocol_minor)

#define NPU_DEFINE_DEV_INFO_PSP(name, _vbnv, id, _psp, fw_path, \
				protocol_major, protocol_minor) \
	_DEFINE_DEV_INFO(name, _vbnv, id, DEFAULT_SRAM_OFFSETS, \
			 _psp, DEFAULT_SMU_OFFSETS, fw_path, protocol_major, protocol_minor)

enum npu_smu_reg_idx {
	SMU_CMD_REG = 0,
	SMU_ARG_REG,
	SMU_INTR_REG,
	SMU_RESP_REG,
	SMU_OUT_REG,
	SMU_MAX_REGS /* Kepp this at the end */
};

enum npu_sram_reg_idx {
	MBOX_CHANN_OFF = 0,
	FW_ALIVE_OFF,
	SRAM_MAX_INDEX /* Keep this at the end */
};

struct npu_bar_off_pair {
	int	bar_idx;
	u32	offset;
};

struct npu_dev_priv {
	const char		*fw_path;
	u64			protocol_major;
	u64			protocol_minor;
	u32			mbox_dev_addr;
	/* If mbox_size is 0, use BAR size. See MBOX_SIZE macro */
	u32			mbox_size;
	u32			sram_dev_addr;
	struct npu_bar_off_pair	sram_offs[SRAM_MAX_INDEX];
	struct npu_bar_off_pair	psp_regs_off[PSP_MAX_REGS];
	struct npu_bar_off_pair	smu_regs_off[SMU_MAX_REGS];
};

struct aie_version {
	u16 major;
	u16 minor;
};

struct aie_tile_metadata {
	u16 row_count;
	u16 row_start;
	u16 dma_channel_count;
	u16 lock_count;
	u16 event_reg_count;
};

struct aie_metadata {
	u32 size;
	u16 cols;
	u16 rows;
	struct aie_version version;
	struct aie_tile_metadata core;
	struct aie_tile_metadata mem;
	struct aie_tile_metadata shim;
};

struct clock_entry {
	char name[16];
	u32 freq_mhz;
};

struct npu_device {
	struct amdxdna_dev		*xdna;
	const struct npu_dev_priv	*priv;
	void			__iomem *sram_base;
	void			__iomem *smu_base;
	void			__iomem *mbox_base;
	struct psp_device		*psp_hdl;
	void				*xrs_hdl;

	struct xdna_mailbox_chann_res	mgmt_x2i;
	struct xdna_mailbox_chann_res	mgmt_i2x;
	u32				mgmt_chan_idx;

	struct aie_version		version;
	struct aie_metadata		metadata;
	struct clock_entry		mp_npu_clock;
	struct clock_entry		h_clock;
};

/* npu_debugfs.c */
void npu_debugfs_init(struct npu_device *ndev);

/* npu_smu.c */
int npu_smu_init(struct npu_device *ndev);
void npu_smu_fini(struct npu_device *ndev);
int npu_smu_set_mpnpu_clock_freq(struct npu_device *ndev, u32 freq_mhz);
int npu_smu_set_hclock_freq(struct npu_device *ndev, u32 freq_mhz);
int npu_smu_set_power_on(struct npu_device *ndev);
int npu_smu_set_power_off(struct npu_device *ndev);

#endif /* __NPU_COMMON_H__ */
