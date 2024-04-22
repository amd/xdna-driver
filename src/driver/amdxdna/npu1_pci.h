/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#ifndef _NPU1_PCI_H_
#define _NPU1_PCI_H_

#include <linux/device.h>
#include <linux/iopoll.h>
#include <linux/io.h>
#include <drm/gpu_scheduler.h>

#include "amdxdna_drv.h"
#include "amdxdna_ctx.h"
#include "npu_mailbox.h"

#define NPU_INTERVAL	20000	/* us */
#define NPU_TIMEOUT	1000000	/* us */

/* Firmware determines device memory base address and size */
#define NPU_DEVM_BASE	0x4000000
#define NPU_DEVM_SIZE	(48 * 1024 * 1024)

#define NDEV2PDEV(ndev) \
	(to_pci_dev((ndev)->xdna->ddev.dev))

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

#define CHAN_SLOT_SZ 0x2000
#define CHANN_INDEX(ndev, rbuf_off) \
	(((rbuf_off) - SRAM_REG_OFF((ndev), MBOX_CHANN_OFF)) / CHAN_SLOT_SZ)

#define MBOX_SIZE(ndev) \
({ \
	typeof(ndev) _ndev = (ndev); \
	((_ndev)->priv->mbox_size) ? (_ndev)->priv->mbox_size : \
	pci_resource_len(NDEV2PDEV(_ndev), (_ndev)->xdna->dev_info->mbox_bar); \
})

#define SMU_MPNPUCLK_FREQ_MAX(ndev) \
	((ndev)->priv->smu_mpnpuclk_freq_max)
#define SMU_HCLK_FREQ_MAX(ndev) \
	((ndev)->priv->smu_hclk_freq_max)

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

enum psp_reg_idx {
	PSP_CMD_REG = 0,
	PSP_ARG0_REG,
	PSP_ARG1_REG,
	PSP_ARG2_REG,
	PSP_NUM_IN_REGS, /* number of input registers */
	PSP_INTR_REG = PSP_NUM_IN_REGS,
	PSP_STATUS_REG,
	PSP_RESP_REG,
	PSP_MAX_REGS /* Keep this at the end */
};

struct psp_config {
	const void	*fw_buf;
	u32		fw_size;
	void __iomem	*psp_regs[PSP_MAX_REGS];
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

struct rt_config {
	u32	type;
	u32	value;
};

/*
 * Define the maximum number of pending commands in a hardware context.
 * Must be power of 2!
 */
#define HWCTX_MAX_CMDS		8
struct npu_hwctx {
	struct amdxdna_gem_obj		*heap;
	void				*mbox_chann;

	struct drm_gpu_scheduler	sched;
	struct drm_sched_entity		entity;

	struct mutex			io_lock; /* protect seq and cmd order */
	struct wait_queue_head		job_free_wq;
	struct amdxdna_sched_job	*pending[HWCTX_MAX_CMDS];
	u32				num_pending;
	u64				seq;
};

struct async_events;

struct npu_device {
	struct amdxdna_dev		*xdna;
	const struct npu_dev_priv	*priv;
	void			__iomem *sram_base;
	void			__iomem *smu_base;
	void			__iomem *mbox_base;
	struct psp_device		*psp_hdl;

	struct xdna_mailbox_chann_res	mgmt_x2i;
	struct xdna_mailbox_chann_res	mgmt_i2x;
	u32				mgmt_chan_idx;

	u32				total_col;
	struct aie_version		version;
	struct aie_metadata		metadata;
	struct clock_entry		mp_npu_clock;
	struct clock_entry		h_clock;

	/* Mailbox and the management channel */
	struct mailbox			*mbox;
	struct mailbox_channel		*mgmt_chann;
	struct async_events		*async_events;
};

#define DEFINE_BAR_OFFSET(reg_name, bar, reg_addr) \
	[reg_name] = {bar##_BAR_INDEX, (reg_addr) - bar##_BAR_BASE}

struct npu_bar_off_pair {
	int	bar_idx;
	u32	offset;
};

struct npu_dev_priv {
	const char		*fw_path;
	u64			protocol_major;
	u64			protocol_minor;
	struct rt_config	rt_config;
#define COL_ALIGN_NONE   0
#define COL_ALIGN_NATURE 1
	u32			col_align;
	u32			mbox_dev_addr;
	/* If mbox_size is 0, use BAR size. See MBOX_SIZE macro */
	u32			mbox_size;
	u32			sram_dev_addr;
	struct npu_bar_off_pair	sram_offs[SRAM_MAX_INDEX];
	struct npu_bar_off_pair	psp_regs_off[PSP_MAX_REGS];
	struct npu_bar_off_pair	smu_regs_off[SMU_MAX_REGS];
	u32			smu_mpnpuclk_freq_max;
	u32			smu_hclk_freq_max;
};

/* npu1_pci.c */
extern const struct amdxdna_dev_ops npu1_ops;

/* npu1_smu.c */
int npu1_smu_init(struct npu_device *ndev);
void npu1_smu_fini(struct npu_device *ndev);
int npu1_smu_set_mpnpu_clock_freq(struct npu_device *ndev, u32 freq_mhz);
int npu1_smu_set_hclock_freq(struct npu_device *ndev, u32 freq_mhz);
int npu1_smu_set_power_on(struct npu_device *ndev);
int npu1_smu_set_power_off(struct npu_device *ndev);

/* npu1_psp.c */
struct psp_device *npu1m_psp_create(struct device *dev, struct psp_config *conf);
int npu1_psp_start(struct psp_device *psp);
void npu1_psp_stop(struct psp_device *psp);

/* npu1_debugfs.c */
void npu1_debugfs_init(struct amdxdna_dev *xdna);

/* npu1_error.c */
int npu1_error_async_events_alloc(struct npu_device *ndev);
void npu1_error_async_events_free(struct npu_device *ndev);
int npu1_error_async_events_send(struct npu_device *ndev);
int npu1_error_async_msg_thread(void *data);

/* npu1_message.c */
int npu1_suspend_fw(struct npu_device *ndev);
int npu1_resume_fw(struct npu_device *ndev);
int npu1_set_runtime_cfg(struct npu_device *ndev, u32 type, u64 value);
int npu1_get_runtime_cfg(struct npu_device *ndev, u32 type, u64 *value);
int npu1_check_protocol_version(struct npu_device *ndev);
int npu1_assign_mgmt_pasid(struct npu_device *ndev, u16 pasid);
int npu1_query_aie_version(struct npu_device *ndev, struct aie_version *version);
int npu1_query_aie_metadata(struct npu_device *ndev, struct aie_metadata *metadata);
int npu1_query_firmware_version(struct npu_device *ndev,
				struct amdxdna_fw_ver *fw_ver);
int npu1_create_context(struct npu_device *ndev, struct amdxdna_hwctx *hwctx);
int npu1_destroy_context(struct npu_device *ndev, struct amdxdna_hwctx *hwctx);
int npu1_map_host_buf(struct npu_device *ndev, u32 context_id, u64 addr, u64 size);
int npu1_query_status(struct npu_device *ndev, char *buf, u32 size, u32 *cols_filled);
int npu1_register_asyn_event_msg(struct npu_device *ndev, dma_addr_t addr, u32 size,
				 void *handle, int (*cb)(void*, const u32 *, size_t));
int npu1_self_test(struct npu_device *ndev);

int npu1_config_cu(struct amdxdna_hwctx *hwctx);
int npu1_execbuf(struct amdxdna_hwctx *hwctx, u32 cu_idx,
		 u32 *payload, u32 payload_len, void *handle,
		 int (*notify_cb)(void *, const u32 *, size_t));

/* npu1_hwctx.c */
int npu1_hwctx_init(struct amdxdna_hwctx *hwctx);
void npu1_hwctx_fini(struct amdxdna_hwctx *hwctx);
int npu1_hwctx_config(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size);
void npu1_hwctx_suspend(struct amdxdna_hwctx *hwctx);
void npu1_hwctx_resume(struct amdxdna_hwctx *hwctx);
int npu1_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq);
int npu1_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout);
void npu1_stop_ctx_by_col_map(struct amdxdna_client *client, u32 col_map);
void npu1_restart_ctx(struct amdxdna_client *client);

#endif /* _NPU1_PCI_H_ */
