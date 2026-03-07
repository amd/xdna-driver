/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2026, Advanced Micro Devices, Inc.
 */

#ifndef _AIE2_PCI_H_
#define _AIE2_PCI_H_

#include <linux/device.h>
#include <linux/iopoll.h>
#include <linux/wait.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/rwsem.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <drm/gpu_scheduler.h>

#include "drm_local/amdxdna_accel.h"
#include "aie2_msg_priv.h"
#include "aie2_tdr.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_ctx.h"
#include "amdxdna_error.h"
#include "amdxdna_gem.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_pm.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif
#include "amdxdna_aie.h"

#define AIE2_INTERVAL	20000	/* us */
#define AIE2_TIMEOUT	1000000	/* us */

/* Firmware version encoding: major in high 32 bits, minor in low 32 bits */
#define AIE2_FW_VERSION(major, minor)	(((u64)(major) << 32) | (minor))
#define AIE2_FW_MAJOR(version)		upper_32_bits(version)
#define AIE2_FW_MINOR(version)		lower_32_bits(version)

/* Firmware determines device memory base address and size */
#define AIE2_DEVM_BASE	0x4000000
#define AIE2_DEVM_SIZE	SZ_64M

#define NDEV2PDEV(ndev) (to_pci_dev((ndev)->xdna->ddev.dev))

#define AIE2_SRAM_OFF(ndev, addr) ((addr) - (ndev)->priv->sram_dev_addr)
#define AIE2_MBOX_OFF(ndev, addr) ((addr) - (ndev)->priv->mbox_dev_addr)

#define SRAM_GET_ADDR(ndev, idx) \
({ \
	typeof(ndev) _ndev = ndev; \
	((_ndev)->sram_base + SRAM_REG_OFF((_ndev), (idx))); \
})

#define CHAN_SLOT_SZ SZ_8K
#define CHANN_INDEX(ndev, rbuf_off) \
	(((rbuf_off) - SRAM_REG_OFF((ndev), MBOX_CHANN_OFF)) / CHAN_SLOT_SZ)

#define MBOX_SIZE(ndev) \
({ \
	typeof(ndev) _ndev = (ndev); \
	((_ndev)->priv->mbox_size) ? (_ndev)->priv->mbox_size : \
	pci_resource_len(NDEV2PDEV(_ndev), (_ndev)->xdna->dev_info->mbox_bar); \
})

#define SMU_DPM_INVALID		0xffffffff
#define SMU_DPM_MAX(ndev) \
	((ndev)->smu.num_dpm_levels - 1)
#define SMU_DPM_TABLE_ENTRY(ndev, level) \
	(&(ndev)->smu.dpm_table[level])

#define ctx_rq_to_ndev(r) \
	((struct amdxdna_dev_hdl *)container_of(r, struct amdxdna_dev_hdl, ctx_rq))
#define ctx_rq_to_xdna_dev(r) \
	(ctx_rq_to_ndev(r)->xdna)

#define AIE2_TDR_WAIT		0
#define AIE2_TDR_SIGNALED	1

#define AIE2_DPT_MSI_ADDR_MASK  GENMASK(23, 0)

struct amdxdna_ctx_priv;
struct aie2_partition;

enum aie2_sram_reg_idx {
	MBOX_CHANN_OFF = 0,
	FW_ALIVE_OFF,
	SRAM_MAX_INDEX /* Keep this at the end */
};

enum rt_config_category {
	AIE2_RT_CFG_INIT,
	AIE2_RT_CFG_CLK_GATING,
};

struct rt_config {
	u32	type;
	u32	value;
	u32	category;
	unsigned long feature_mask;
};

#ifdef AMDXDNA_DEVEL
struct ctx_pdi {
	int			id;
	int			registered;
	size_t			size;
	void			*addr;
	dma_addr_t		dma_addr;
};
#endif

/*
 * Define the maximum number of outstanding commands in a context.
 * Must be power of 2!
 */
#define CTX_MAX_CMDS			4
#define get_job_idx(seq) ((seq) & (CTX_MAX_CMDS - 1))
struct amdxdna_ctx_priv {
	struct amdxdna_gem_obj		*heap;
#ifdef AMDXDNA_DEVEL
	struct ctx_pdi			*pdi_infos;
#endif

	struct amdxdna_gem_obj		*cmd_buf[CTX_MAX_CMDS];
#ifdef AMDXDNA_DEVEL
	struct amdxdna_sched_job	*pending[CTX_MAX_CMDS];
#endif
	struct semaphore		job_sem;

	/* Driver needs to wait for all jobs freed before fini DRM scheduler */
	wait_queue_head_t		job_free_waitq;

	u32				orig_num_col;
	u32				req_dpm_level;

	/* For context runqueue */
	/* When there is ongoing IO, use this sem avoid runqueue disconnect ctx */
	struct rw_semaphore		io_sem;
	atomic64_t			job_pending_cnt;
	wait_queue_head_t		connect_waitq;
	int				idle_cnt;
	bool				active;
	u64				disconn_cnt;
	bool				force_yield;
#define CTX_STATE_DISCONNECTED		0x0
#define CTX_STATE_DISPATCHED		0x1
#define CTX_STATE_CONNECTED		0x2
#define CTX_STATE_DISCONNECTING		0x3
#define CTX_STATE_DEBUG			0xFE
#define CTX_STATE_DEAD			0xFF
	u32				status;
	int				errno; /* when CTX_STATE_DEAD */
	bool				should_block;
	int				priority;
	struct aie2_partition		*part;
	struct completion		parts_work_comp;

	/* Hardware context related in below */
	u32				id;
	void				*mbox_chann;
	struct drm_gpu_scheduler	sched;
	struct drm_sched_entity		entity;
};

enum aie2_dev_status {
	AIE2_DEV_UNINIT,
	AIE2_DEV_INIT,
	AIE2_DEV_START,
};

struct aie2_partition {
#define CTX_RQ_REALTIME		0
#define CTX_RQ_HIGH		1
#define CTX_RQ_NORMAL		2
#define CTX_RQ_LOW		3
#define CTX_RQ_NUM_QUEUE	4
	struct list_head	runqueue[CTX_RQ_NUM_QUEUE];
	struct list_head	conn_list;
	struct aie2_ctx_rq	*rq;

	struct work_struct	sched_work;

	u32			start_col;
	u32			end_col;
	u32			max_hwctx;
	u32			max_rt_ctx;

	u32			ctx_cnt;
	u32			hwctx_cnt;
	u32			rt_ctx_cnt;
};

struct aie2_ctx_rq {
	u32			ctx_limit;
	u32			hwctx_limit;
	u32			start_col;
	u32			total_cols;
	u32			start_col_orig;

	struct workqueue_struct	*work_q;
	struct work_struct	parts_work;
	struct list_head	parts_work_waitq;
	bool			paused;

	/*
	 * Above are static members which initial by aie2_rq_init().
	 * Below are dynamic members, protected by xdna->dev_lock
	 */
	struct list_head	disconn_list;
	struct aie2_partition	*parts;
	/* the number of activated parts */
	u32			num_parts;
	u32			ctx_cnt;
	u32			rt_ctx_cnt;
	int			*ctx_width_resv;
	u32			max_cols;
};

struct async_events;

struct aie2_exec_msg_ops {
	int (*init_cu_req)(struct amdxdna_gem_obj *cmd_bo, void *req,
			   size_t *size, u32 *msg_op);
	int (*init_dpu_req)(struct amdxdna_gem_obj *cmd_bo, void *req,
			    size_t *size, u32 *msg_op);
	void (*init_chain_req)(void *req, u64 slot_addr, size_t size, u32 cmd_cnt);
	int (*fill_cf_slot)(struct amdxdna_gem_obj *cmd_bo, void *slot, size_t *size);
	int (*fill_dpu_slot)(struct amdxdna_gem_obj *cmd_bo, void *slot, size_t *size);
	int (*fill_preempt_slot)(struct amdxdna_gem_obj *cmd_bo, void *slot, size_t *size);
	int (*fill_elf_slot)(struct amdxdna_gem_obj *cmd_bo, void *slot, size_t *size);
	u32 (*get_chain_msg_op)(u32 cmd_op);
};

struct amdxdna_dev_hdl {
	struct amdxdna_dev		*xdna;
	const struct amdxdna_dev_priv	*priv;
	void			__iomem *sram_base;
	void			__iomem *smu_base;
	void			__iomem *mbox_base;
	struct psp_device		*psp_hdl;
	struct smu_device		*smu_hdl;

	struct xdna_mailbox_chann_info	mgmt_info;
	u64				mgmt_fw_version;

	u32				total_col;
	struct aie_version		version;
	struct aie_metadata		metadata;
	unsigned long			feature_mask;
	struct aie2_exec_msg_ops	*exec_msg_ops;

	/*power management and clock */
	int				pw_mode;
	enum aie_power_state		power_state;
	u32				sys_eff_factor;
	u32				dpm_level;
	u32				dft_dpm_level;
	u32				max_dpm_level;
	u32				*dpm_cnt;
	u32				clk_gating;
	u32				npuclk_freq;
	u32				hclk_freq;
	u32				max_tops;
	u32				curr_tops;
	bool				force_preempt_enabled;
	bool				frame_boundary_preempt;

	/* Mailbox and the management channel */
	struct mailbox			*mbox;
	struct mailbox_channel		*mgmt_chann;
	struct async_events		*async_events;

	u32				dev_status;
	u32				hwctx_cnt;

	/*
	 * The aie2_lock should be used in non critical path for below purposes
	 *   - Exclusively send message to mgmt channel
	 *   - Protect hwctx_cnt
	 *   - Protect SMU set dpm, power on/off
	 *
	 * Some code path needs to make more than one of above atomic, such as,
	 * aie2_hwctx_start() needs to send messages, access hwctx_cnt
	 * aie2_mgmt_fw_init() needs to send multiple messages, etc.
	 */
	struct mutex			aie2_lock;

	struct aie2_ctx_rq		ctx_rq;

	struct aie2_tdr			tdr;

	struct amdxdna_async_err_cache	async_errs_cache; // For async error event cache
};

#define DEFINE_BAR_OFFSET(reg_name, bar, reg_addr) \
	[reg_name] = {bar##_BAR_INDEX, (reg_addr) - bar##_BAR_BASE}

struct aie2_bar_off_pair {
	int	bar_idx;
	u32	offset;
};

struct aie2_hw_ops {
	int (*set_dpm)(struct amdxdna_dev_hdl *ndev, u32 dpm_level);
};

enum aie2_fw_feature {
	AIE2_NPU_COMMAND,
	AIE2_PREEMPT,
	AIE2_FEATURE_MAX
};

struct aie2_fw_feature_tbl {
	enum aie2_fw_feature feature;
	u64 min_fw_version;
	u64 max_fw_version;  /* 0 = no upper limit */
};

#define AIE2_FEATURE_ON(ndev, feature)	test_bit(feature, &(ndev)->feature_mask)

struct amdxdna_dev_priv {
	const char				*fw_path;
	u64					min_fw_version;
	const struct rt_config			*rt_config;
	const struct dpm_clk_freq		*dpm_clk_tbl;
	const struct msg_op_ver			*optional_msg;
	const struct rt_cfg_ver			*optional_cfg;
	const struct aie2_fw_feature_tbl	*fw_feature_tbl;

	u32					col_opc;
	u32					mbox_dev_addr;
	/* If mbox_size is 0, use BAR size. See MBOX_SIZE macro */
	u32					mbox_size;
	u32					hwctx_limit; /* Hardware determine */
	u32					ctx_limit; /* Driver determine */
	u32					temporal_only;
	u32					sram_dev_addr;
	struct aie_bar_off_pair			sram_offs[SRAM_MAX_INDEX];
	struct aie_bar_off_pair			psp_regs_off[PSP_MAX_REGS];
	struct aie_bar_off_pair			smu_regs_off[SMU_MAX_REGS];
	struct aie_hw_ops			hw_ops;
#ifdef AMDXDNA_DEVEL
	struct rt_config			priv_load_cfg;
#endif
};

extern const struct amdxdna_dev_ops aie2_ops;

static inline void aie2_calc_intr_reg(struct xdna_mailbox_chann_info *info)
{
	info->intr_reg = info->i2x.mb_head_ptr_reg + 4;
}

int aie2_runtime_cfg(struct amdxdna_dev_hdl *ndev,
		     enum rt_config_category category, u32 *val);

/* aie2_pci.c */
#define AIE2_BIT_BYPASS_POWER_SWITCH	0 /* NOSYS */
#define AIE2_BIT_BYPASS_SET_FREQ	1
#define AIE2_BIT_BYPASS_FW_LOAD		2 /* NOSYS */
extern uint aie2_control_flags;
extern const struct amdxdna_dev_ops aie2_ops;
int aie2_check_protocol(struct amdxdna_dev_hdl *ndev, u32 fw_major, u32 fw_minor);

/* aie2_smu.c */
int aie2_smu_start(struct amdxdna_dev_hdl *ndev);
void aie2_smu_stop(struct amdxdna_dev_hdl *ndev);
int npu1_set_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level);
int npu4_set_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level);
int aie2_smu_get_mpnpu_clock_freq(struct amdxdna_dev_hdl *ndev);
int aie2_smu_get_hclock_freq(struct amdxdna_dev_hdl *ndev);
int aie2_smu_set_power_on(struct amdxdna_dev_hdl *ndev);
int aie2_smu_set_power_off(struct amdxdna_dev_hdl *ndev);
int aie2_smu_get_power_state(struct amdxdna_dev_hdl *ndev);

/* aie2_pm.c */
int aie2_pm_init(struct amdxdna_dev_hdl *ndev);
void aie2_pm_fini(struct amdxdna_dev_hdl *ndev);
int aie2_pm_set_mode(struct amdxdna_dev_hdl *ndev, int target);
#define aie2_pm_add_dpm_level(d, l) aie2_pm_set_dft_dpm_level(d, l, true)
#define aie2_pm_del_dpm_level(d, l) aie2_pm_set_dft_dpm_level(d, l, false)
void aie2_pm_set_dft_dpm_level(struct amdxdna_dev_hdl *ndev, u32 level, bool add);

/* aie2_tdr.c */
void aie2_tdr_start(struct amdxdna_dev *xdna);
void aie2_tdr_stop(struct amdxdna_dev *xdna);

static inline bool aie2_pm_is_turbo(struct amdxdna_dev_hdl *ndev)
{
	return ndev->pw_mode == POWER_MODE_TURBO;
}

/* aie2_psp.c */
struct psp_device *aie2m_psp_create(struct device *dev, struct psp_config *conf);
void aie2_psp_destroy(struct device *dev, void *psp_hdl);
int aie2_psp_start(struct psp_device *psp);
void aie2_psp_stop(struct psp_device *psp);
int aie2_psp_waitmode_poll(struct psp_device *psp);

/* aie2_debugfs.c */
void aie2_debugfs_init(struct amdxdna_dev *xdna);

/* aie2_error.c */
int aie2_error_async_events_alloc(struct amdxdna_dev_hdl *ndev);
void aie2_error_async_events_free(struct amdxdna_dev_hdl *ndev);
int aie2_error_async_msg_thread(void *data);
int aie2_error_async_cache_init(struct amdxdna_dev_hdl *ndev);
int aie2_error_get_last_async(struct amdxdna_dev *xdna,
			      struct amdxdna_async_err_cache *err_cache, u32 num_errs,
			      void *errors);

/* aie2_message.c */
void aie2_msg_init(struct amdxdna_dev_hdl *ndev);
bool aie2_is_supported_msg(struct amdxdna_dev_hdl *ndev, enum aie2_msg_opcode opcode);
int aie2_suspend_fw(struct amdxdna_dev_hdl *ndev);
int aie2_resume_fw(struct amdxdna_dev_hdl *ndev);
int aie2_set_runtime_cfg(struct amdxdna_dev_hdl *ndev, u32 type, u64 value);
int aie2_get_runtime_cfg(struct amdxdna_dev_hdl *ndev, u32 type, u64 *value);
int aie2_fine_preemption(struct amdxdna_dev_hdl *ndev, bool disable);
int aie2_force_preemption(struct amdxdna_dev_hdl *ndev, u32 hwctx_id);
int aie2_frame_boundary_preemption(struct amdxdna_dev_hdl *ndev, bool enable);
int aie2_update_prop_time_quota(struct amdxdna_dev_hdl *ndev,
				struct amdxdna_ctx *ctx, u32 us);
int aie2_check_protocol_version(struct amdxdna_dev_hdl *ndev);
int aie2_calibrate_time(struct amdxdna_dev_hdl *ndev);
int aie2_assign_mgmt_pasid(struct amdxdna_dev_hdl *ndev, u16 pasid);
int aie2_query_aie_telemetry(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			     u32 type, u32 size, struct aie_version *version);
int aie2_get_app_health(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			u32 context_id, u32 size);
int aie2_get_aie_coredump(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			  u32 context_id, u32 num_bufs);
void aie2_reset_app_health_report(struct app_health_report *r);
int aie2_query_aie_version(struct amdxdna_dev_hdl *ndev, struct aie_version *version);
int aie2_query_aie_metadata(struct amdxdna_dev_hdl *ndev, struct aie_metadata *metadata);
int aie2_query_aie_firmware_version(struct amdxdna_dev_hdl *ndev,
				    struct amdxdna_fw_ver *fw_ver);
int aie2_get_dev_revision(struct amdxdna_dev_hdl *ndev, enum aie2_dev_revision *rev);
int aie2_create_context(struct amdxdna_dev_hdl *ndev, struct amdxdna_ctx *ctx,
			struct xdna_mailbox_chann_info *info);
int aie2_destroy_context(struct amdxdna_dev_hdl *ndev, struct amdxdna_ctx *ctx);
int aie2_map_host_buf(struct amdxdna_dev_hdl *ndev, u32 context_id, u64 addr, u64 size);
int aie2_query_aie_status(struct amdxdna_dev_hdl *ndev, char *buf, u32 size, u32 *cols_filled);
int aie2_register_asyn_event_msg(struct amdxdna_dev_hdl *ndev,
				 struct amdxdna_mgmt_dma_hdl *dma_hdl, void *handle,
				 int (*cb)(void*, void __iomem *, size_t));
int aie2_self_test(struct amdxdna_dev_hdl *ndev);
#ifdef AMDXDNA_DEVEL
int aie2_register_pdis(struct amdxdna_ctx *ctx);
int aie2_unregister_pdis(struct amdxdna_ctx *ctx);
int aie2_legacy_config_cu(struct amdxdna_ctx *ctx);
#endif
int aie2_config_fw_log(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
		       size_t size, u32 *msi_id, u32 *msi_addr);
int aie2_set_log_level(struct amdxdna_dev_hdl *ndev, enum fw_log_level level);
int aie2_set_log_format(struct amdxdna_dev_hdl *ndev, enum fw_log_format format);
int aie2_set_log_destination(struct amdxdna_dev_hdl *ndev, enum fw_log_destination destination);
int aie2_start_fw_trace(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			size_t size, u32 categories, u32 *msi_idx, u32 *msi_address);
int aie2_stop_fw_trace(struct amdxdna_dev_hdl *ndev);
int aie2_set_trace_categories(struct amdxdna_dev_hdl *ndev, u32 categories);
int aie2_rw_aie_reg(struct amdxdna_dev_hdl *ndev, enum aie2_access_type type,
		    u8 ctx_id, u8 row, u8 col, u32 addr, u32 *value);
int aie2_rw_aie_mem(struct amdxdna_dev_hdl *ndev, enum aie2_access_type type,
		    u8 ctx_id, u8 row, u8 col, u32 aie_addr, u64 dram_addr, u32 size);

int aie2_config_cu(struct amdxdna_ctx *ctx);
int aie2_execbuf(struct amdxdna_ctx *ctx, struct amdxdna_sched_job *job,
		 int (*notify_cb)(void *, void __iomem *, size_t));
int aie2_cmdlist_single_execbuf(struct amdxdna_ctx *ctx,
				struct amdxdna_sched_job *job,
				int (*notify_cb)(void *, void __iomem *, size_t));
int aie2_cmdlist_multi_execbuf(struct amdxdna_ctx *ctx,
			       struct amdxdna_sched_job *job,
			       int (*notify_cb)(void *, void __iomem *, size_t));
int aie2_sync_bo(struct amdxdna_ctx *ctx, struct amdxdna_sched_job *job,
		 int (*notify_cb)(void *, void __iomem *, size_t));
int aie2_config_debug_bo(struct amdxdna_ctx *ctx, struct amdxdna_sched_job *job,
			 int (*notify_cb)(void *, void __iomem *, size_t));

/* aie2_ctx.c */
int aie2_ctx_init(struct amdxdna_ctx *ctx);
void aie2_ctx_fini(struct amdxdna_ctx *ctx);
int aie2_ctx_connect(struct amdxdna_ctx *ctx);
void aie2_ctx_disconnect(struct amdxdna_ctx *ctx, bool wait);
int aie2_ctx_config(struct amdxdna_ctx *ctx, u32 type, u64 value, void *buf, u32 size);
int aie2_cmd_submit(struct amdxdna_sched_job *job,
		    u32 *syncobj_hdls, u64 *syncobj_points, u32 syncobj_cnt, u64 *seq);
int aie2_cmd_wait(struct amdxdna_ctx *ctx, u64 seq, u32 timeout);
struct dma_fence *aie2_cmd_get_out_fence(struct amdxdna_ctx *ctx, u64 seq);
void aie2_hmm_invalidate(struct amdxdna_gem_obj *abo, unsigned long cur_seq);
void aie2_dump_ctx(struct amdxdna_ctx *ctx);

/* aie2_hwctx.c */
int aie2_hwctx_start(struct amdxdna_ctx *ctx);
void aie2_hwctx_stop(struct amdxdna_ctx *ctx);

/* aie2_ctx_runqueue.c */
int aie2_rq_init(struct aie2_ctx_rq *rq);
void aie2_rq_fini(struct aie2_ctx_rq *rq);
int aie2_rq_context_limit(struct aie2_ctx_rq *rq);
int aie2_rq_active_context(struct aie2_ctx_rq *rq);
bool aie2_rq_handle_idle_ctx(struct aie2_ctx_rq *rq);
bool aie2_rq_is_all_context_stuck(struct aie2_ctx_rq *rq);
void aie2_rq_dump_all(struct aie2_ctx_rq *rq);
void aie2_rq_stop_all(struct aie2_ctx_rq *rq);
void aie2_rq_restart_all(struct aie2_ctx_rq *rq);
int aie2_rq_show(struct aie2_ctx_rq *rq, struct seq_file *m);

int aie2_rq_add(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx);
void aie2_rq_del(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx);
int aie2_rq_submit_enter(struct aie2_ctx_rq *rq, struct amdxdna_ctx *ctx);
void aie2_rq_submit_exit(struct amdxdna_ctx *ctx);
void aie2_rq_yield(struct amdxdna_ctx *ctx);

static inline bool aie2_is_ctx_connected(struct amdxdna_ctx *ctx)
{
	return ctx->priv->status == CTX_STATE_CONNECTED;
}

static inline bool aie2_is_ctx_rt(struct amdxdna_ctx *ctx)
{
	return ctx->priv->priority == CTX_RQ_REALTIME;
}

static inline bool aie2_is_ctx_debug(struct amdxdna_ctx *ctx)
{
	return ctx->priv->status == CTX_STATE_DEBUG;
}

static inline bool aie2_is_ctx_fatal(struct amdxdna_ctx *ctx)
{
	if (ctx->priv->status == CTX_STATE_DEAD)
		return true;

	return aie2_is_ctx_debug(ctx);
}

static inline bool aie2_is_ctx_disconnected(struct amdxdna_ctx *ctx)
{
	return ctx->priv->status == CTX_STATE_DISCONNECTED;
}

static inline bool aie2_is_ctx_dispatched(struct amdxdna_ctx *ctx)
{
	return ctx->priv->status == CTX_STATE_DISPATCHED;
}

static inline bool aie2_is_ctx_disconnecting(struct amdxdna_ctx *ctx)
{
	return ctx->priv->status == CTX_STATE_DISCONNECTING;
}

static inline bool ctx_should_stop(struct amdxdna_ctx *ctx)
{
	return aie2_is_ctx_connected(ctx) || aie2_is_ctx_disconnecting(ctx) ||
	       aie2_is_ctx_debug(ctx);
}

/* aie2_dpt.c */
int aie2_fw_log_init(struct amdxdna_dev *xdna, size_t size, u8 level);
int aie2_fw_log_fini(struct amdxdna_dev *xdna);
int aie2_fw_log_config(struct amdxdna_dev *xdna, u8 level);
void aie2_fw_log_parse(struct amdxdna_dev *xdna, char *buffer, size_t size);

int aie2_fw_trace_init(struct amdxdna_dev *xdna, size_t size, u32 categories);
int aie2_fw_trace_fini(struct amdxdna_dev *xdna);
int aie2_fw_trace_config(struct amdxdna_dev *xdna, u32 categories);
void aie2_fw_trace_parse(struct amdxdna_dev *xdna, char *buffer, size_t size);

#endif /* _AIE2_PCI_H_ */

