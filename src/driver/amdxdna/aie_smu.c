// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <drm/drm_device.h>
#include <drm/drm_managed.h>
#include <drm/drm_print.h>
#include <linux/iopoll.h>

#include "drm_local/amdxdna_accel.h"
#include "aie_common.h"
#include "amdxdna_pci_drv.h"

#define SMU_REG(s, reg) ((s)->smu_regs[reg])

struct smu_device {
	struct drm_device	*ddev;
	struct smu_config	conf;
	void __iomem		*smu_regs[SMU_MAX_REGS];
};

int aie_smu_exec(struct smu_device *smu, u32 reg_cmd, u32 reg_arg, u32 *out)
{
	u32 resp;
	int ret;

	writel(0, SMU_REG(smu, SMU_RESP_REG));
	writel(reg_arg, SMU_REG(smu, SMU_ARG_REG));
	writel(reg_cmd, SMU_REG(smu, SMU_CMD_REG));

	/* Clear and set SMU_INTR_REG to kick off */
	writel(0, SMU_REG(smu, SMU_INTR_REG));
	writel(1, SMU_REG(smu, SMU_INTR_REG));

	ret = readx_poll_timeout(readl, SMU_REG(smu, SMU_RESP_REG), resp,
				 resp, AIE_INTERVAL, AIE_TIMEOUT);
	if (ret) {
		drm_err(smu->ddev, "smu cmd %d timed out", reg_cmd);
		return ret;
	}

	if (out)
		*out = readl(SMU_REG(smu, SMU_OUT_REG));

	if (resp != SMU_RESULT_OK) {
		drm_err(smu->ddev, "smu cmd %d failed, 0x%x", reg_cmd, resp);
		return -EINVAL;
	}

	return 0;
}

struct smu_device *aiem_smu_create(struct drm_device *ddev, struct smu_config *conf)
{
	struct smu_device *smu;

	smu = drmm_kzalloc(ddev, sizeof(*smu), GFP_KERNEL);
	if (!smu)
		return NULL;

	smu->ddev = ddev;
	memcpy(smu->smu_regs, conf->smu_regs, sizeof(smu->smu_regs));

	return smu;
}

