/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2026, Advanced Micro Devices, Inc.
 */

#ifndef _AIE4_PCI_H_
#define _AIE4_PCI_H_

#include <linux/device.h>
#include <linux/iopoll.h>
#include <linux/io.h>
#include <linux/wait.h>

#include "amdxdna_pci_drv.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_error.h"
#include "amdxdna_aie.h"
#include "amdxdna_mgmt.h"
#include "aie4_msg_priv.h"

#define AIE4_INTERVAL		20000	/* us */
#ifdef AMDXDNA_DEVEL
#define AIE4_TIMEOUT		(1000000 * 1000) /* us */
#else
#define AIE4_TIMEOUT		1000000	/* us */
#endif
#define AIE4_CTX_HYSTERESIS_US	1000	/* us */

#define MAX_NUM_CERTS		6

#define CERTFW_MAX_SIZE		(SZ_32K + SZ_256)

#define AIE4_DPT_MSI_ADDR_MASK  GENMASK(23, 0)

extern int kernel_mode_submission;

struct clock_entry {
	char name[16];
	u32 freq_mhz;
};

struct rt_config_clk_gating {
	const u32	*types;
	u32		num_types;
	u32		value_enable;
	u32		value_disable;
};

struct amdxdna_ctx_priv {
	struct amdxdna_ctx		*ctx;
	struct amdxdna_gem_obj		*umq_bo;
	u64				*umq_read_index;
	u64				*umq_write_index;
	u64				write_index;
	struct host_queue_packet	*umq_pkts;
	struct host_indirect_packet_data *umq_indirect_pkts;
	u64				umq_indirect_pkts_dev_addr;

	struct work_struct		job_work;
	bool				job_aborting;
	struct workqueue_struct		*job_work_q;
	wait_queue_head_t		job_list_wq;
	struct list_head		pending_job_list;
	struct list_head		running_job_list;

	void			__iomem	*doorbell_addr;

	u32				meta_bo_hdl;
	struct col_entry		*col_entry;
	u32				hw_ctx_id;
#define CTX_STATE_DISCONNECTED		0x0
#define CTX_STATE_CONNECTED		0x1
	u32                             status;

	/* CERT Simulation for debug only, remove later. */
	struct workqueue_struct		*cert_work_q;
	struct work_struct		cert_work;
	u64				cert_timeout_seq;
	u64				cert_error_seq;
	u64				cert_read_index;

	bool					cached_health_valid;
	struct aie4_msg_app_health_report	*cached_health_report;
};

enum aie4_dev_status {
	AIE4_DEV_UNINIT = 0,
	AIE4_DEV_INIT,
	AIE4_DEV_START,
};

struct amdxdna_dev_priv {
	const char		*npufw_path;
	const char		*certfw_path;
	u64			mbox_info_off;
	u32			doorbell_off;
	struct rt_config_clk_gating	clk_gating;
	const struct dpm_clk_freq	*dpm_clk_tbl;
	struct aie_bar_off_pair        psp_regs_off[PSP_MAX_REGS];
	struct aie_bar_off_pair        smu_regs_off[SMU_MAX_REGS];
	struct aie_hw_ops              hw_ops;
};

struct async_events;

struct amdxdna_dev_hdl {
	struct amdxdna_dev		*xdna;
	const struct amdxdna_dev_priv	*priv;
	void				*xrs_hdl;
	struct psp_device		*psp_hdl;

	u32				partition_id;

	u32				total_col;
	struct aie_version		version;
	struct aie_metadata		metadata;
	struct clock_entry		mp_npu_clock;
	struct clock_entry		h_clock;

	/* Mailbox and the management channel */
	struct mailbox			*mbox;
	struct mailbox_channel		*mgmt_chann;

	u32				dev_status;

	struct list_head		col_entry_list;
	struct mutex			col_list_lock; // lock for col_entry_list
	void			__iomem *doorbell_base;
	void			__iomem *mbox_base;
	void			__iomem *rbuf_base;
	void			__iomem *psp_base;
	void			__iomem *smu_base;

	int				pw_mode;
	enum aie_power_state		power_state;
	struct timer_list		event_timer;
	bool				clk_gate_enabled;
	u32				dpm_level;
	bool				force_preempt_enabled;

	int				num_vfs;

	struct async_events		*async_events;
	struct amdxdna_async_err_cache	async_errs_cache; // For async error event cache

	struct amdxdna_mgmt_dma_hdl	*mpnpu_work_buffer;

	/* Protect mgmt_chann */
	struct mutex			aie4_lock;
};

struct col_entry {
	struct amdxdna_dev_hdl	*ndev;
	u32			msix_idx;
	int			col_irq;
	struct kref		col_ref_count;
	wait_queue_head_t	col_event;
	struct list_head	col_list;
	bool			needs_reset;
};

/* common util inline functions */
static inline int is_npu3_pf_dev(const struct pci_dev *pdev)
{
	return (pdev->device == 0x17F2 || pdev->device == 0x1B0B);
}

static inline int is_npu3_vf_dev(const struct pci_dev *pdev)
{
	return (pdev->device == 0x17F3 || pdev->device == 0x1B0C);
}

/* aie4_debugfs.c */
void aie4_debugfs_init(struct amdxdna_dev *xdna);

/* aie4_error.c */
int aie4_error_async_events_alloc(struct amdxdna_dev_hdl *ndev);
void aie4_error_async_events_free(struct amdxdna_dev_hdl *ndev);
int aie4_error_async_msg_thread(void *data);
int aie4_error_get_last_async(struct amdxdna_dev *xdna,
			      struct amdxdna_async_err_cache *err_cache, u32 num_errs,
			      void *errors);

/* aie4_message.c*/
int aie4_suspend_fw(struct amdxdna_dev_hdl *ndev);
int aie4_resume_fw(struct amdxdna_dev_hdl *ndev);
int aie4_force_preemption(struct amdxdna_dev_hdl *ndev);
int aie4_check_firmware_version(struct amdxdna_dev_hdl *ndev);
int aie4_register_asyn_event_msg(struct amdxdna_dev_hdl *ndev,
				 struct amdxdna_mgmt_dma_hdl *dma_hdl, void *handle,
				 int (*cb)(void*, void __iomem *, size_t));
int aie4_query_aie_status(struct amdxdna_dev_hdl *ndev, char *buf, u32 size, u32 *cols_filled);
int aie4_query_aie_version(struct amdxdna_dev_hdl *ndev, struct aie_version *version);
int aie4_query_aie_metadata(struct amdxdna_dev_hdl *ndev, struct aie_metadata *metadata);
int aie4_query_aie_telemetry(struct amdxdna_dev_hdl *ndev, u32 type, u32 pasid, dma_addr_t addr,
			     u32 size);
int aie4_set_pm_msg(struct amdxdna_dev_hdl *ndev, u32 target);
int aie4_calibrate_clock(struct amdxdna_dev_hdl *ndev);
int aie4_start_fw_log(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl, u8 level,
		      size_t size, u32 *msi_idx, u32 *msi_address);
int aie4_set_log_level(struct amdxdna_dev_hdl *ndev, u8 level);
int aie4_stop_fw_log(struct amdxdna_dev_hdl *ndev);
int aie4_start_fw_trace(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			size_t size, u32 categories, u32 *msi_idx, u32 *msi_address);
int aie4_set_trace_categories(struct amdxdna_dev_hdl *ndev, u32 categories);
int aie4_stop_fw_trace(struct amdxdna_dev_hdl *ndev);
int aie4_attach_work_buffer(struct amdxdna_dev_hdl *ndev, u32 pasid, dma_addr_t addr, u32 size);
int aie4_detach_work_buffer(struct amdxdna_dev_hdl *ndev);
int aie4_rw_aie_reg(struct amdxdna_dev_hdl *ndev, enum aie4_aie_debug_op op,
		    u32 ctx_id, u8 row, u8 col, u32 addr, u32 *value);
int aie4_rw_aie_mem(struct amdxdna_dev_hdl *ndev, enum aie4_aie_debug_op op,
		    u32 ctx_id, u8 row, u8 col, u32 aie_addr, u64 dram_addr,
		    u32 size, u32 pasid);
int aie4_get_aie_coredump(struct amdxdna_dev_hdl *ndev, struct amdxdna_mgmt_dma_hdl *dma_hdl,
			  u32 context_id, u32 pasid, u32 num_bufs);
void aie4_reset_prepare(struct amdxdna_dev *xdna);
int aie4_reset_done(struct amdxdna_dev *xdna);
int aie4_set_ctx_hysteresis(struct amdxdna_dev_hdl *ndev, u32 timeout_us);
int aie4_set_ctx_timeout(struct amdxdna_dev_hdl *ndev, u32 timeout_ms);

/* aie4_hwctx.c */
int aie4_ctx_init(struct amdxdna_ctx *ctx);
void aie4_ctx_fini(struct amdxdna_ctx *ctx);
void aie4_ctx_suspend(struct amdxdna_ctx *ctx, bool wait);
int aie4_ctx_resume(struct amdxdna_ctx *ctx);
int aie4_cmd_submit(struct amdxdna_sched_job *job,
		    u32 *syncobj_hdls, u64 *syncobj_points, u32 syncobj_cnt, u64 *seq);
int aie4_cmd_wait(struct amdxdna_ctx *ctx, u64 seq, u32 timeout);
int aie4_ctx_config(struct amdxdna_ctx *ctx, u32 type, u64 value, void *buf, u32 size);
int aie4_parse_priority(u32 priority);

/* aie4_smu.c */
int aie4_smu_start(struct amdxdna_dev_hdl *ndev);
void aie4_smu_stop(struct amdxdna_dev_hdl *ndev);
int aie4_set_dpm(struct amdxdna_dev_hdl *ndev, u32 dpm_level);
int aie4_smu_set_power_on(struct amdxdna_dev_hdl *ndev);
int aie4_smu_set_power_off(struct amdxdna_dev_hdl *ndev);
int aie4_smu_get_power_state(struct amdxdna_dev_hdl *ndev);

/* aie4_pm.c */
int aie4_pm_init(struct amdxdna_dev_hdl *ndev);
void aie4_pm_fini(struct amdxdna_dev_hdl *ndev);
bool aie4_pm_is_turbo(struct amdxdna_dev_hdl *ndev);
int aie4_pm_set_mode(struct amdxdna_dev_hdl *ndev, int target);
int aie4_get_tops(struct amdxdna_dev_hdl *ndev, u64 *max, u64 *curr);

/* aie4_psp.c */
struct psp_device *aie4_psp_create(struct device *dev, struct aie4_psp_config *conf);
int aie4_psp_start(struct psp_device *psp);
void aie4_psp_stop(struct psp_device *psp);
int aie4_psp_waitmode_poll(struct psp_device *psp);

/* aie4_pci.c */
int aie4_create_context(struct amdxdna_dev_hdl *ndev, struct amdxdna_ctx *ctx);
int aie4_destroy_context(struct amdxdna_dev_hdl *ndev, struct amdxdna_ctx *ctx,
			 int graceful);

/* aie4_dpt.c */
int aie4_fw_log_init(struct amdxdna_dev *xdna, size_t size, u8 level);
int aie4_fw_log_config(struct amdxdna_dev *xdna, u8 level);
int aie4_fw_log_fini(struct amdxdna_dev *xdna);
void aie4_fw_log_parse(struct amdxdna_dev *xdna, char *buffer, size_t size);
int aie4_fw_trace_init(struct amdxdna_dev *xdna, size_t size, u32 categories);
int aie4_fw_trace_fini(struct amdxdna_dev *xdna);
int aie4_fw_trace_config(struct amdxdna_dev *xdna, u32 categories);
void aie4_fw_trace_parse(struct amdxdna_dev *xdna, char *buffer, size_t size);

/* aie4_sriov.c */
int aie4_sriov_configure(struct amdxdna_dev *xdna, int num_vfs);

extern const struct amdxdna_dev_ops aie4_ops;

#endif /* _AIE4_PCI_H_ */
