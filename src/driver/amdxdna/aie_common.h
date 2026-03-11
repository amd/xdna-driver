/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AIE_COMMON_H_
#define _AIE_COMMON_H_

#include "amdxdna_aie.h"

#define AIE_INTERVAL	20000	/* us */
#define AIE_TIMEOUT	1000000	/* us */

#define PSP_STATUS_READY	BIT(31)

/* PSP commands */
#define PSP_VALIDATE		1
#define PSP_START		2
#define PSP_RELEASE_TMR		3
#define PSP_VALIDATE_CERT	4

/* PSP special arguments */
#define PSP_START_COPY_FW	1

/* PSP response error code */
#define PSP_ERROR_CANCEL	0xFFFF0002
#define PSP_ERROR_BAD_STATE	0xFFFF0007

#define PSP_FW_ALIGN		0x10000
#define PSP_CFW_ALIGN		0x8000
#define PSP_POLL_INTERVAL	20000	/* us */
#define PSP_POLL_TIMEOUT	1000000	/* us */
#define PSP_NOTIFY_INTR		0xD007BE11

#define PSP_REG_BAR(ndev, idx) ((ndev)->priv->psp_regs_off[(idx)].bar_idx)
#define PSP_REG_OFF(ndev, idx) ((ndev)->priv->psp_regs_off[(idx)].offset)
#define PSP_REG(p, reg) ((p)->psp_regs[reg])

/* SMU commands */
#define AIE_SMU_POWER_ON		0x3
#define AIE_SMU_POWER_OFF		0x4
/* For SMU v0 */
#define AIE_SMU_SET_MPNPUCLK_FREQ	0x5
#define AIE_SMU_SET_HCLK_FREQ		0x6
/* For SMU v1 */
#define AIE_SMU_SET_SOFT_DPMLEVEL	0x7
#define AIE_SMU_SET_HARD_DPMLEVEL	0x8

#define SMU_RESULT_OK	1
#define SMU_REG_BAR(ndev, idx) ((ndev)->priv->smu_regs_off[(idx)].bar_idx)
#define SMU_REG_OFF(ndev, idx) ((ndev)->priv->smu_regs_off[(idx)].offset)

enum psp_reg_idx {
	PSP_CMD_REG = 0,
	PSP_ARG0_REG,
	PSP_ARG1_REG,
	PSP_ARG2_REG,
	PSP_NUM_IN_REGS, /* number of input registers */
	PSP_INTR_REG = PSP_NUM_IN_REGS,
	PSP_STATUS_REG,
	PSP_RESP_REG,
	PSP_PWAITMODE_REG,
	PSP_MAX_REGS /* Keep this at the end */
};

enum aie_smu_reg_idx {
	SMU_CMD_REG = 0,
	SMU_ARG_REG,
	SMU_INTR_REG,
	SMU_RESP_REG,
	SMU_OUT_REG,
	SMU_MAX_REGS /* Keep this at the end */
};

enum aie_smu_rev {
	SMU_REVISION_NONE = 0,
	SMU_REVISION_NPU1,
	SMU_REVISION_NPU4,
	SMU_REVISION_MAX
};

struct aie_bar_off_pair {
	int	bar_idx;
	u32	offset;
};

struct psp_config {
	const void	*fw_buf;
	u32		fw_size;
	const void	*certfw_buf;
	u32		certfw_size;
	void __iomem	*psp_regs[PSP_MAX_REGS];
};

struct psp_device {
	struct drm_device *ddev;
	struct device	  *dev;
	struct psp_config conf;
	u32		  fw_buf_sz;
	u64		  fw_paddr;
	void		  *fw_buffer;
	dma_addr_t	  fw_dma_handle;
	u32		  certfw_buf_sz;
	u64		  certfw_paddr;
	void		  *certfw_buffer;
	void __iomem	  *psp_regs[PSP_MAX_REGS];
#ifdef HAVE_xen_phy_dma_ops
	struct device	  xen_dma_dev;
#endif
};

struct smu_config {
	void __iomem	*smu_regs[SMU_MAX_REGS];
};

struct drm_device;
struct smu_device;

struct psp_device *aiem_psp_create(struct drm_device *ddev, struct device *dev,
				   struct psp_config *conf);
struct smu_device *aiem_smu_create(struct drm_device *ddev, struct smu_config *conf);
int aie_smu_exec(struct smu_device *smu, u32 reg_cmd, u32 reg_arg, u32 *out);

#endif /* _AIE_COMMON_H_ */
