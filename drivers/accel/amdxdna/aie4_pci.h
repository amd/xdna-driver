/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AIE4_PCI_H_
#define _AIE4_PCI_H_

#include <linux/device.h>
#include <linux/iopoll.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "aie.h"
#include "aie4_msg_priv.h"	/* struct aie4_async_ctx_error */
#include "amdxdna_error.h"
#include "amdxdna_mailbox.h"

struct host_queue_packet;
struct host_indirect_packet_data;
struct amdxdna_hwctx;

/* Default context switch hysteresis timeout in microseconds. */
#define AIE4_CTX_HYSTERESIS_US	1000

struct cert_comp {
	struct amdxdna_dev_hdl          *ndev;
	u32                             msix_idx;
	int                             irq;
	struct kref                     kref;
	wait_queue_head_t               waitq;
};

/*
 * aie4 kernel-submission job states (stored in amdxdna_sched_job priv.aie4.state).
 * Anonymous enum - the aie4_job_state identifier is already a field-access macro.
 */
enum {
	AIE4_JOB_STATE_INIT,
	AIE4_JOB_STATE_PENDING,
	AIE4_JOB_STATE_SUBMITTING,
	AIE4_JOB_STATE_SUBMITTED,
	AIE4_JOB_STATE_DONE,
};

struct amdxdna_hwctx_priv {
	struct amdxdna_hwctx            *hwctx;
	struct amdxdna_gem_obj          *umq_bo;
	u64                             *umq_read_index;
	u64                             *umq_write_index;
	/* Last valid read_index, returned when a sampled index looks invalid. */
	u64                             last_read_index;

	struct cert_comp                *cert_comp;
	u32                             hw_ctx_id;
	/* Snapshot of kernel_mode_submission for this ctx's lifetime. */
	bool                            kernel_submit;

	/*
	 * Last CERT async context-error report for this ctx, cached by the async
	 * error worker and consumed by the kernel-mode timeout/recovery path.
	 * Both the flag and the multi-word report body are protected by io_lock
	 * (cached only for kernel-mode contexts); the flag alone is insufficient
	 * because the worker can overwrite the body while a reader consumes it.
	 */
	bool                            cached_ctx_error_valid;
	struct aie4_async_ctx_error     cached_ctx_error;

	/* Kernel-mode submission: driver fills the user HSA queue and rings
	 * the doorbell.  umq_pkts/umq_indirect_pkts alias the user umq_bo;
	 * their content is driver-owned, only read_index is trusted from the
	 * shared queue.
	 */
	u64                             write_index;
	struct host_queue_packet        *umq_pkts;
	struct host_indirect_packet_data *umq_indirect_pkts;
	u64                             umq_indirect_pkts_dev_addr;
	void                    __iomem *doorbell_addr;

	struct mutex                    io_lock; /* serialize submit, protect job lists */
	struct list_head                pending_job_list;
	/* Head of pending_job_list, updated under io_lock; read locklessly by the
	 * submit wait condition so it never takes a lock inside wait_event().
	 */
	struct amdxdna_sched_job        *pending_head;
	struct list_head                running_job_list;
	wait_queue_head_t               job_list_wq;
	struct work_struct              job_work;
	struct workqueue_struct         *job_work_q;
};

struct amdxdna_dev_priv {
	const char              *npufw_path;
	const char              *certfw_path;
	u32			mbox_bar;
	u32			mbox_rbuf_bar;
	u64			mbox_info_off;
	u32			doorbell_off;

	struct aie_bar_off_pair	psp_regs_off[PSP_MAX_REGS];
	struct aie_bar_off_pair	smu_regs_off[SMU_MAX_REGS];

	const struct dpm_clk_freq	*dpm_clk_tbl;
	const struct aie_hw_ops		*hw_ops;
};

struct amdxdna_dev_hdl {
	struct aie_device		aie;
	const struct amdxdna_dev_priv	*priv;
	void			__iomem *mbox_base;
	void			__iomem *rbuf_base;
	void			__iomem *doorbell_base;

	struct mailbox			*mbox;
	u32				partition_id;
	u32				num_vfs;
	u32				total_col;
	u32				max_dpm_level;

	struct dpm_clk_freq		dpm_clk_tbl[AIE4_MAX_DPM_LEVEL_COUNT];

	struct xarray                   cert_comp_xa; /* device level indexed by msix id */
	struct mutex                    cert_comp_lock; /* protects cert_comp operations*/

	struct amdxdna_msg_buf_hdl	*work_buf_hdl;

	u8				pw_mode;

	/* aie4 kernel-mode submission default; tunable via debugfs. */
	bool				kernel_submit;

	/*
	 * Context switch hysteresis timeout in microseconds; pushed to the
	 * firmware at hw start and tunable at runtime via debugfs.
	 */
	u32				ctx_switch_hysteresis_us;

	struct amdxdna_drm_query_firmware_version cert_version;
};

struct aie4_msg_context_config_cert_logging;

/* aie4_ctx.c */
int aie4_hwctx_init(struct amdxdna_hwctx *hwctx);
void aie4_hwctx_fini(struct amdxdna_hwctx *hwctx);
int aie4_hwctx_config(struct amdxdna_hwctx *hwctx, u32 type, u64 value,
		      void *buf, u32 size);
int aie4_cmd_wait(struct amdxdna_hwctx *hwctx, u64 seq, u32 timeout);
int aie4_cmd_submit(struct amdxdna_hwctx *hwctx, struct amdxdna_sched_job *job, u64 *seq);
int aie4_hwctx_create(struct amdxdna_hwctx *hwctx);
void aie4_hwctx_destroy(struct amdxdna_hwctx *hwctx);
void aie4_hwctx_resume_jobs(struct amdxdna_hwctx *hwctx);
void aie4_hwctx_cleanup_running_jobs(struct amdxdna_hwctx *hwctx, bool errored);
void aie4_fill_health_data(struct amdxdna_gem_obj *cmd_abo, struct amdxdna_hwctx *hwctx);

/* aie4_sriov.c */
#if IS_ENABLED(CONFIG_PCI_IOV)
int aie4_sriov_configure(struct amdxdna_dev *xdna, int num_vfs);
int aie4_create_vfs(struct amdxdna_dev_hdl *ndev, int num_vfs);
int aie4_sriov_stop(struct amdxdna_dev_hdl *ndev);
int aie4_vfs_alive(struct amdxdna_dev *xdna);
#else
#define aie4_sriov_configure NULL
static inline int aie4_sriov_stop(struct amdxdna_dev_hdl *ndev) { return 0; }
static inline int aie4_create_vfs(struct amdxdna_dev_hdl *ndev, int num_vfs) { return 0; }
static inline int aie4_vfs_alive(struct amdxdna_dev *xdna) { return 0; }
#endif

/* aie4_message.c */
int aie4_query_aie_metadata(struct amdxdna_dev_hdl *ndev,
			    struct amdxdna_drm_query_aie_metadata *metadata);
int aie4_query_aie_version(struct amdxdna_dev_hdl *ndev,
			   struct amdxdna_drm_query_aie_version *version);
int aie4_query_npu_firmware_version(struct amdxdna_dev_hdl *ndev,
				    struct amdxdna_drm_query_firmware_version *fw_version);
int aie4_query_dpm_level(struct amdxdna_dev_hdl *ndev,
			 u32 *aieclk_dpm_level, u32 *npuhclk_dpm_level);
int aie4_init_dpm_freq_table(struct amdxdna_dev_hdl *ndev);
int aie4_query_cert_firmware_version(struct amdxdna_dev_hdl *ndev,
				     struct amdxdna_drm_query_firmware_version *cert_version);
int aie4_suspend_fw(struct amdxdna_dev_hdl *ndev);
int aie4_attach_work_buffer(struct amdxdna_dev_hdl *ndev, dma_addr_t addr, u32 size);
int aie4_msg_set_power_mode(struct amdxdna_dev_hdl *ndev, u8 power_mode);
int aie4_force_preemption(struct amdxdna_dev_hdl *ndev);
int aie4_set_ctx_hysteresis(struct amdxdna_dev_hdl *ndev, u32 timeout_us);
int aie4_configure_hw_context_cert_log(struct amdxdna_dev_hdl *ndev,
				       u32 hw_context_id, u32 property,
				       const struct aie4_msg_context_config_cert_logging *cl);
int aie4_calibrate_clock(struct amdxdna_dev_hdl *ndev);
void aie4_msg_init(struct amdxdna_dev_hdl *ndev);
u32 aie4_msg_pasid(struct amdxdna_client *client);
int aie4_register_asyn_event_msg(struct amdxdna_dev_hdl *ndev, dma_addr_t addr, u32 size,
				 void *handle, int (*cb)(void *, void __iomem *, size_t));

/* aie4_error.c */
extern const struct aie_error_lut_set aie4_error_luts;
int aie4_async_event_register(struct aie_device *aie, dma_addr_t addr, u32 size,
			      void *handle, int (*cb)(void *, void __iomem *, size_t));
bool aie4_handle_dev_event(struct aie_device *aie, u32 type, void *vaddr);
int aie4_get_array_async_error(struct amdxdna_dev_hdl *ndev,
			       struct amdxdna_drm_get_array *args);

enum aie4_fw_feature {
	AIE4_GET_COREDUMP,
	AIE4_RW_ACCESS,
	AIE4_FW_LOG,
	AIE4_FW_TRACE,
	AIE4_CALIBRATE_CLOCK,
	AIE4_HSA_COMMAND,
	AIE4_FEATURE_MAX
};

int aie4_get_aie_coredump(struct amdxdna_hwctx *hwctx,
			  struct amdxdna_msg_buf_hdl *list_hdl,
			  u32 num_bufs);
int aie4_rw_aie_reg(struct amdxdna_hwctx *hwctx, bool is_read,
		    u8 row, u8 col, u32 addr, u32 *value);
int aie4_rw_aie_mem(struct amdxdna_hwctx *hwctx, bool is_read,
		    u8 row, u8 col, u32 aie_addr,
		    dma_addr_t dram_addr, u32 size);

int aie4_set_runtime_cfg(struct amdxdna_dev_hdl *ndev, u32 type,
			 const void *data, size_t size);
int aie4_start_fw_log(struct amdxdna_dev_hdl *ndev,
		      struct amdxdna_msg_buf_hdl *buf_hdl, u8 level,
		      size_t size, u32 *msi_idx, u32 *msi_address);
int aie4_start_fw_trace(struct amdxdna_dev_hdl *ndev,
			struct amdxdna_msg_buf_hdl *buf_hdl, size_t size,
			u32 categories, u32 *msi_idx, u32 *msi_address);

/* aie4_pci.c */
int aie4_fw_log_init(struct amdxdna_dev *xdna, size_t size, u32 level);
int aie4_fw_log_config(struct amdxdna_dev *xdna, u32 level);
int aie4_fw_log_fini(struct amdxdna_dev *xdna);

int aie4_fw_trace_init(struct amdxdna_dev *xdna, size_t size, u32 categories);
int aie4_fw_trace_config(struct amdxdna_dev *xdna, u32 categories);
int aie4_fw_trace_fini(struct amdxdna_dev *xdna);

extern const struct amdxdna_dev_ops aie4_pf_ops;
extern const struct amdxdna_dev_ops aie4_vf_ops;
extern const struct amdxdna_dev_ops aie4_classic_ops;

#endif /* _AIE4_PCI_H_ */
