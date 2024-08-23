/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AIE2_PCI_H_
#define _AIE2_PCI_H_

#include <linux/device.h>
#include <linux/iopoll.h>
#include <linux/io.h>
#include <drm/gpu_scheduler.h>

#include "drm_local/amdxdna_accel.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_ctx.h"
#include "amdxdna_gem.h"
#include "amdxdna_mailbox.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#define SMU_REVISION_V0 0x0
#define SMU_REVISION_V1 0x1

#define AIE2_INTERVAL	20000	/* us */
#define AIE2_TIMEOUT	1000000	/* us */

/* Firmware determines device memory base address and size */
#define AIE2_DEVM_BASE	0x4000000
#define AIE2_DEVM_SIZE	(64 * 1024 * 1024)

#define NDEV2PDEV(ndev) \
	(to_pci_dev((ndev)->xdna->ddev.dev))

#define AIE2_SRAM_OFF(ndev, addr) \
	((addr) - (ndev)->priv->sram_dev_addr)
#define AIE2_MBOX_OFF(ndev, addr) \
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
#define SMU_DPM_MAX(ndev) \
	((ndev)->priv->smu_dpm_max)

#define SMU_NPU_DPM_TABLE_ENTRY(ndev, level) \
	(&ndev->priv->smu_npu_dpm_clk_table[level])

enum aie2_smu_reg_idx {
	SMU_CMD_REG = 0,
	SMU_ARG_REG,
	SMU_INTR_REG,
	SMU_RESP_REG,
	SMU_OUT_REG,
	SMU_MAX_REGS /* Kepp this at the end */
};

enum aie2_sram_reg_idx {
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

enum dpm_level {
	DPM_LEVEL_0=0,
	DPM_LEVEL_1,
	DPM_LEVEL_2,
	DPM_LEVEL_3,
	DPM_LEVEL_4,
	DPM_LEVEL_5,
	DPM_LEVEL_6,
	DPM_LEVEL_7,
	DPM_LEVEL_MAX,
};

struct dpm_clk {
	u32 npuclk;
	u32 hclk;
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

struct clock {
	char name[16];
	u32 max_freq_mhz;
	u32 freq_mhz;
#if defined(CONFIG_DEBUG_FS)
	u32 dbg_freq_mhz;
#endif
};

struct smu {
	struct clock		mp_npu_clock;
	struct clock		h_clock;
	u32			curr_dpm_level;
#define SMU_POWER_OFF 0
#define SMU_POWER_ON  1
	u32			power_state;
};

#ifdef AMDXDNA_DEVEL
struct hwctx_pdi {
	int			id;
	int			registered;
	size_t			size;
	void			*addr;
	dma_addr_t		dma_addr;
};
#endif
/*
 * Define the maximum number of pending commands in a hardware context.
 * Must be power of 2!
 */
#define HWCTX_MAX_CMDS		4
#define get_job_idx(seq) ((seq) & (HWCTX_MAX_CMDS - 1))
struct amdxdna_hwctx_priv {
	struct amdxdna_gem_obj		*heap;
	void				*mbox_chann;
#ifdef AMDXDNA_DEVEL
	struct hwctx_pdi		*pdi_infos;
#endif

	struct drm_gpu_scheduler	sched;
	struct drm_sched_entity		entity;

	struct mutex			io_lock; /* protect seq and cmd order */
	struct wait_queue_head		job_free_wq;
	struct amdxdna_sched_job	*pending[HWCTX_MAX_CMDS];
	u32				num_pending;

	struct amdxdna_gem_obj		*cmd_buf[HWCTX_MAX_CMDS];
};

struct async_events;

struct amdxdna_dev_hdl {
	struct amdxdna_dev		*xdna;
	const struct amdxdna_dev_priv	*priv;
	void			__iomem *sram_base;
	void			__iomem *smu_base;
	void			__iomem *mbox_base;
	struct psp_device		*psp_hdl;

	struct xdna_mailbox_chann_res	mgmt_x2i;
	struct xdna_mailbox_chann_res	mgmt_i2x;
	u32				mgmt_chan_idx;
	u32				mgmt_prot_major;
	u32				mgmt_prot_minor;

	u32				total_col;
	u32				smu_curr_dpm_level;
	struct aie_version		version;
	struct aie_metadata		metadata;
	struct smu			smu;
	enum amdxdna_power_mode_type	pw_mode;

	/* Mailbox and the management channel */
	struct mailbox			*mbox;
	struct mailbox_channel		*mgmt_chann;
	struct async_events		*async_events;
};

#define DEFINE_BAR_OFFSET(reg_name, bar, reg_addr) \
	[reg_name] = {bar##_BAR_INDEX, (reg_addr) - bar##_BAR_BASE}

struct aie2_bar_off_pair {
	int	bar_idx;
	u32	offset;
};

struct rt_config {
	u32	type;
	u32	value;
};

struct rt_config_clk_gating {
	const u32	*types;
	u32		num_types;
	u32		value_enable;
	u32		value_disable;
};

struct amdxdna_dev_priv {
	const char			*fw_path;
	u64				protocol_major;
	u64				protocol_minor;
	const struct rt_config		*rt_config;
	u32				num_rt_cfg;
#define COL_ALIGN_NONE   0
#define COL_ALIGN_NATURE 1
	u32				col_align;
	u32				mbox_dev_addr;
	/* If mbox_size is 0, use BAR size. See MBOX_SIZE macro */
	u32				mbox_size;
	u32				sram_dev_addr;
	struct aie2_bar_off_pair	sram_offs[SRAM_MAX_INDEX];
	struct aie2_bar_off_pair	psp_regs_off[PSP_MAX_REGS];
	struct aie2_bar_off_pair	smu_regs_off[SMU_MAX_REGS];
	struct rt_config_clk_gating	clk_gating;
	u32				smu_mpnpuclk_freq_max;
	u32				smu_hclk_freq_max;
	/* npu1: 0, not support dpm; npu2+: support dpm up to 7 */
	u32				smu_dpm_max;
	u32				smu_rev;
	const struct dpm_clk		*smu_npu_dpm_clk_table;
	u32				smu_npu_dpm_levels;
#ifdef AMDXDNA_DEVEL
	struct rt_config		priv_load_cfg;
#endif
};

/* aie2_pci.c */
extern const struct amdxdna_dev_ops aie2_ops;
int aie2_check_protocol(struct amdxdna_dev_hdl *ndev, u32 fw_major, u32 fw_minor);

/* aie2_smu.c */
void aie2_smu_setup(struct amdxdna_dev_hdl *ndev);
int aie2_smu_start(struct amdxdna_dev_hdl *ndev);
void aie2_smu_stop(struct amdxdna_dev_hdl *ndev);
int aie2_smu_set_clock_freq(struct amdxdna_dev_hdl *ndev, struct clock *clock, u32 freq_mhz);
char *aie2_smu_get_mpnpu_clock_name(struct amdxdna_dev_hdl *ndev);
char *aie2_smu_get_hclock_name(struct amdxdna_dev_hdl *ndev);
int aie2_smu_get_mpnpu_clock_freq(struct amdxdna_dev_hdl *ndev);
int aie2_smu_get_hclock_freq(struct amdxdna_dev_hdl *ndev);
int aie2_smu_set_power_on(struct amdxdna_dev_hdl *ndev);
int aie2_smu_set_power_off(struct amdxdna_dev_hdl *ndev);
int aie2_smu_get_power_state(struct amdxdna_dev_hdl *ndev);
int aie2_smu_get_dpm_level(struct amdxdna_dev_hdl *ndev);
int aie2_smu_set_dpm_level(struct amdxdna_dev_hdl *ndev, u32 dpm_level, bool cache);
void aie2_smu_prepare_s0i3(struct amdxdna_dev_hdl *ndev);

/* aie2_psp.c */
struct psp_device *aie2m_psp_create(struct device *dev, struct psp_config *conf);
int aie2_psp_start(struct psp_device *psp);
void aie2_psp_stop(struct psp_device *psp);

/* aie2_debugfs.c */
void aie2_debugfs_init(struct amdxdna_dev *xdna);

/* aie2_error.c */
int aie2_error_async_events_alloc(struct amdxdna_dev_hdl *ndev);
void aie2_error_async_events_free(struct amdxdna_dev_hdl *ndev);
int aie2_error_async_events_send(struct amdxdna_dev_hdl *ndev);
int aie2_error_async_msg_thread(void *data);

/* aie2_message.c */
int aie2_suspend_fw(struct amdxdna_dev_hdl *ndev);
int aie2_resume_fw(struct amdxdna_dev_hdl *ndev);
int aie2_set_runtime_cfg(struct amdxdna_dev_hdl *ndev, u32 type, u64 value);
int aie2_get_runtime_cfg(struct amdxdna_dev_hdl *ndev, u32 type, u64 *value);
int aie2_check_protocol_version(struct amdxdna_dev_hdl *ndev);
int aie2_assign_mgmt_pasid(struct amdxdna_dev_hdl *ndev, u16 pasid);
int aie2_get_telemetry(struct amdxdna_dev_hdl *ndev, u32 type, dma_addr_t addr, u32 size);
int aie2_query_aie_version(struct amdxdna_dev_hdl *ndev, struct aie_version *version);
int aie2_query_aie_metadata(struct amdxdna_dev_hdl *ndev, struct aie_metadata *metadata);
int aie2_query_firmware_version(struct amdxdna_dev_hdl *ndev,
				struct amdxdna_fw_ver *fw_ver);
int aie2_create_context(struct amdxdna_dev_hdl *ndev, struct amdxdna_hwctx *hwctx);
int aie2_destroy_context(struct amdxdna_dev_hdl *ndev, struct amdxdna_hwctx *hwctx);
int aie2_map_host_buf(struct amdxdna_dev_hdl *ndev, u32 context_id, u64 addr, u64 size);
int aie2_query_status(struct amdxdna_dev_hdl *ndev, char *buf, u32 size, u32 *cols_filled);
int aie2_register_asyn_event_msg(struct amdxdna_dev_hdl *ndev, dma_addr_t addr, u32 size,
				 void *handle, int (*cb)(void*, const u32 *, size_t));
int aie2_self_test(struct amdxdna_dev_hdl *ndev);
#ifdef AMDXDNA_DEVEL
int aie2_register_pdis(struct amdxdna_hwctx *hwctx);
int aie2_unregister_pdis(struct amdxdna_hwctx *hwctx);
int aie2_legacy_config_cu(struct amdxdna_hwctx *hwctx);
#endif

int aie2_config_cu(struct amdxdna_hwctx *hwctx);
int aie2_execbuf(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
		 int (*notify_cb)(void *, const u32 *, size_t));
int aie2_cmdlist_single_execbuf(struct amdxdna_hwctx *hwctx,
				struct amdxdna_sched_job *job,
				int (*notify_cb)(void *, const u32 *, size_t));
int aie2_cmdlist_multi_execbuf(struct amdxdna_hwctx *hwctx,
			       struct amdxdna_sched_job *job,
			       int (*notify_cb)(void *, const u32 *, size_t));
int aie2_sync_bo(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
		 int (*notify_cb)(void *, const u32 *, size_t));
int aie2_config_debug_bo(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job,
			 int (*notify_cb)(void *, const u32 *, size_t));

/* aie2_hwctx.c */
int aie2_hwctx_init(struct amdxdna_hwctx *hwctx);
void aie2_hwctx_fini(struct amdxdna_hwctx *hwctx);
int aie2_hwctx_config(struct amdxdna_hwctx *hwctx, u32 type, u64 value, void *buf, u32 size);
void aie2_hwctx_suspend(struct amdxdna_hwctx *hwctx);
void aie2_hwctx_resume(struct amdxdna_hwctx *hwctx);
int aie2_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq);
int aie2_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout);
void aie2_hmm_invalidate(struct amdxdna_gem_obj *abo, unsigned long cur_seq);
void aie2_stop_ctx(struct amdxdna_client *client);
void aie2_restart_ctx(struct amdxdna_client *client);
void aie2_stop_ctx_by_col_map(struct amdxdna_client *client, u32 col_map);

/* aie2_pm.c */
int aie2_pm_start(struct amdxdna_dev_hdl *ndev);
void aie2_pm_stop(struct amdxdna_dev_hdl *ndev);
int aie2_pm_set_mode(struct amdxdna_dev_hdl *ndev, enum amdxdna_power_mode_type target);

#endif /* _AIE2_PCI_H_ */
