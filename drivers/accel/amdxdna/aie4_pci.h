/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AIE4_PCI_H_
#define _AIE4_PCI_H_

#include <linux/pci.h>

#include "aie4.h"

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

extern const struct amdxdna_dev_ops aie4_pf_ops;
extern const struct amdxdna_dev_ops aie4_vf_ops;
extern const struct amdxdna_dev_ops aie4_classic_ops;

#endif /* _AIE4_PCI_H_ */
