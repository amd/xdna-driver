// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_device.h>

#include "aie4_msg_priv.h"
#include "aie4_pci.h"
#include "amdxdna_pci_drv.h"
#include "amdxdna_sensors.h"

#define NPU3_MBOX_BAR		0

#define NPU3_MBOX_BUFFER_BAR	2
#define NPU3_MBOX_INFO_OFF	0x0

#define NPU3_DOORBELL_BAR       2
#define NPU3_DOORBELL_OFF       0x0

/* PCIe BAR Index for NPU3 */
#define NPU3_REG_BAR_INDEX	0
#define NPU3_PSP_BAR_INDEX      4
#define NPU3_SMU_BAR_INDEX      5

#define MMNPU_APERTURE3_BASE    0x3810000
#define MMNPU_APERTURE4_BASE    0x3B10000

#define NPU3_PSP_BAR_BASE       MMNPU_APERTURE3_BASE
#define NPU3_SMU_BAR_BASE       MMNPU_APERTURE4_BASE

#define MPASP_C2PMSG_123_ALT_1  0x3810AEC
#define MPASP_C2PMSG_156_ALT_1  0x3810B70
#define MPASP_C2PMSG_157_ALT_1  0x3810B74
#define MPASP_C2PMSG_73_ALT_1   0x3810A24

#define MP1_C2PMSG_59_ALT_1     0x3B109EC
#define MP1_C2PMSG_61_ALT_1     0x3B109F4
#define MP1_C2PMSG_60_ALT_1     0x3B109F0

#define NPU3_DPM_TOPS(ndev, hclk) (4096 * (ndev)->total_col * (hclk) / 1000000)

static const struct amdxdna_fw_feature_tbl npu3_fw_feature_table[] = {
	{ .major = 6, .min_minor = 0 },
	{ .features = BIT_U64(AIE4_GET_COREDUMP), .major = 6, .min_minor = 0 },
	{ .features = BIT_U64(AIE4_RW_ACCESS), .major = 6, .min_minor = 0 },
	{ .features = BIT_U64(AIE4_FW_LOG), .major = 6, .min_minor = 0 },
	{ .features = BIT_U64(AIE4_CALIBRATE_CLOCK), .major = 6, .min_minor = 0 },
	{ 0 }
};

static const struct amdxdna_fw_feature_tbl npu3_cert_feature_table[] = {
	{ .major = 1, .min_minor = 0 },
	{ .features = BIT_U64(AIE4_HSA_COMMAND), .major = 1, .min_minor = 0 },
	{ 0 }
};

const struct dpm_clk_freq npu3_dpm_clk_table[] = {
	{  400,  400},
	{  960,  576},
	{ 1108,  576},
	{ 1200,  847},
	{ 1200, 1200},
	{ 1200, 1200},
	{ 1200, 1200},
	{ 1200, 1200},
	{ 0 }
};

static int npu3_set_dpm(struct aie_device *aie, u32 dpm_level)
{
	struct amdxdna_dev_hdl *ndev = aie->xdna->dev_handle;
	int max_dpm_level = 0;

	while (ndev->priv->dpm_clk_tbl[max_dpm_level].hclk)
		max_dpm_level++;
	max_dpm_level--;

	if (max_dpm_level < 0 || dpm_level > max_dpm_level) {
		XDNA_ERR(aie->xdna, "Invalid dpm level, max:%d, request:%d",
			 max_dpm_level, dpm_level);
		return -EINVAL;
	}

	aie->npuclk_freq = ndev->priv->dpm_clk_tbl[dpm_level].npuclk;
	aie->hclk_freq = ndev->priv->dpm_clk_tbl[dpm_level].hclk;
	aie->max_tops = NPU3_DPM_TOPS(ndev, ndev->priv->dpm_clk_tbl[max_dpm_level].hclk);
	aie->curr_tops = NPU3_DPM_TOPS(ndev, aie->hclk_freq);

	XDNA_DBG(aie->xdna, "MP-NPU clock %d, H clock %d\n",
		 aie->npuclk_freq, aie->hclk_freq);

	ndev->max_dpm_level = max_dpm_level;
	return 0;
}

static int npu3_update_counters(struct aie_device *aie)
{
	struct amdxdna_dev_hdl *ndev = aie->xdna->dev_handle;
	struct amdxdna_sensors npu_metrics = {};
	int ret;

	ret = amdxdna_get_sensors(&npu_metrics);
	if (ret)
		return ret;

	aie->npuclk_freq = npu_metrics.mpnpuclk_freq;
	aie->hclk_freq = npu_metrics.npuclk_freq;
	aie->curr_tops = NPU3_DPM_TOPS(ndev, aie->hclk_freq);

	return 0;
}

const struct aie_hw_ops npu3_hw_ops = {
	.set_dpm = npu3_set_dpm,
	.update_counters = npu3_update_counters,
};

static const struct amdxdna_dev_priv npu3_dev_priv = {
	.npufw_path             = "npu.dev.sbin",
	.certfw_path            = "cert.dev.sbin",
	.dpm_clk_tbl		= npu3_dpm_clk_table,
	.mbox_bar		= NPU3_MBOX_BAR,
	.mbox_rbuf_bar		= NPU3_MBOX_BUFFER_BAR,
	.mbox_info_off		= NPU3_MBOX_INFO_OFF,
	.doorbell_off		= NPU3_DOORBELL_OFF,
	.psp_regs_off   = {
		DEFINE_BAR_OFFSET(PSP_CMD_REG,    NPU3_PSP, MPASP_C2PMSG_123_ALT_1),
		DEFINE_BAR_OFFSET(PSP_ARG0_REG,   NPU3_PSP, MPASP_C2PMSG_156_ALT_1),
		DEFINE_BAR_OFFSET(PSP_ARG1_REG,   NPU3_PSP, MPASP_C2PMSG_157_ALT_1),
		DEFINE_BAR_OFFSET(PSP_ARG2_REG,   NPU3_PSP, MPASP_C2PMSG_123_ALT_1),
		DEFINE_BAR_OFFSET(PSP_INTR_REG,   NPU3_PSP, MPASP_C2PMSG_73_ALT_1),
		DEFINE_BAR_OFFSET(PSP_STATUS_REG, NPU3_PSP, MPASP_C2PMSG_123_ALT_1),
		DEFINE_BAR_OFFSET(PSP_RESP_REG,   NPU3_PSP, MPASP_C2PMSG_156_ALT_1),
		/* npu3 doesn't use 8th pwaitmode register */
	},
	.smu_regs_off   = {
		DEFINE_BAR_OFFSET(SMU_CMD_REG,  NPU3_SMU, MP1_C2PMSG_59_ALT_1),
		DEFINE_BAR_OFFSET(SMU_ARG_REG,  NPU3_SMU, MP1_C2PMSG_61_ALT_1),
		DEFINE_BAR_OFFSET(SMU_INTR_REG, NPU3_SMU, MMNPU_APERTURE4_BASE),
		DEFINE_BAR_OFFSET(SMU_RESP_REG, NPU3_SMU, MP1_C2PMSG_60_ALT_1),
		DEFINE_BAR_OFFSET(SMU_OUT_REG,  NPU3_SMU, MP1_C2PMSG_61_ALT_1),
	},
	.hw_ops = &npu3_hw_ops,
};

static const struct amdxdna_dev_priv npu3_dev_vf_priv = {
	/* vf device does not load firmware */
	.dpm_clk_tbl		= npu3_dpm_clk_table,
	.mbox_bar		= NPU3_MBOX_BAR,
	.mbox_rbuf_bar		= NPU3_MBOX_BUFFER_BAR,
	.mbox_info_off		= NPU3_MBOX_INFO_OFF,
	/* vf device does not have smu and psp */
	.hw_ops = &npu3_hw_ops,
};

const struct amdxdna_dev_info dev_npu3_pf_info = {
	.mbox_bar		= NPU3_MBOX_BAR,
	.sram_bar		= NPU3_MBOX_BUFFER_BAR,
	.psp_bar                = NPU3_PSP_BAR_INDEX,
	.smu_bar		= NPU3_SMU_BAR_INDEX,
	.default_vbnv		= "RyzenAI-npu3-pf",
	.device_type		= AMDXDNA_DEV_TYPE_PF,
	.dev_priv		= &npu3_dev_priv,
	.fw_feature_tbl		= npu3_fw_feature_table,
	.cert_feature_tbl	= npu3_cert_feature_table,
	.ops			= &aie4_pf_ops,
	.luts			= &aie4_error_luts,
	.async_max_status_code	= MAX_AIE4_MSG_STATUS_CODE,
};

const struct amdxdna_dev_info dev_npu3_vf_info = {
	.mbox_bar		= NPU3_MBOX_BAR,
	.sram_bar		= NPU3_MBOX_BUFFER_BAR,
	.doorbell_bar		= NPU3_DOORBELL_BAR,
	.default_vbnv		= "RyzenAI-npu3-vf",
	.device_type		= AMDXDNA_DEV_TYPE_UMQ,
	.dev_priv		= &npu3_dev_vf_priv,
	.fw_feature_tbl		= npu3_fw_feature_table,
	.cert_feature_tbl	= npu3_cert_feature_table,
	.ops			= &aie4_vf_ops,
	.luts			= &aie4_error_luts,
	.async_max_status_code	= MAX_AIE4_MSG_STATUS_CODE,
};

const struct amdxdna_dev_info dev_npu3_classic_info = {
	.mbox_bar		= NPU3_MBOX_BAR,
	.sram_bar		= NPU3_MBOX_BUFFER_BAR,
	.psp_bar                = NPU3_PSP_BAR_INDEX,
	.smu_bar		= NPU3_SMU_BAR_INDEX,
	.doorbell_bar		= NPU3_DOORBELL_BAR,
	.default_vbnv		= "RyzenAI-npu3",
	.device_type		= AMDXDNA_DEV_TYPE_UMQ,
	.dev_priv		= &npu3_dev_priv,
	.fw_feature_tbl		= npu3_fw_feature_table,
	.cert_feature_tbl	= npu3_cert_feature_table,
	.ops			= &aie4_classic_ops,
	.luts			= &aie4_error_luts,
	.async_max_status_code	= MAX_AIE4_MSG_STATUS_CODE,
};

const struct amdxdna_dev_info dev_npu9_pf_info = {
	.mbox_bar		= NPU3_MBOX_BAR,
	.sram_bar		= NPU3_MBOX_BUFFER_BAR,
	.psp_bar		= NPU3_PSP_BAR_INDEX,
	.smu_bar		= NPU3_SMU_BAR_INDEX,
	.default_vbnv		= "RyzenAI-npu9-pf",
	.device_type		= AMDXDNA_DEV_TYPE_PF,
	.dev_priv		= &npu3_dev_priv,
	.fw_feature_tbl		= npu3_fw_feature_table,
	.cert_feature_tbl	= npu3_cert_feature_table,
	.ops			= &aie4_pf_ops,
	.luts			= &aie4_error_luts,
	.async_max_status_code	= MAX_AIE4_MSG_STATUS_CODE,
};

const struct amdxdna_dev_info dev_npu9_vf_info = {
	.mbox_bar		= NPU3_MBOX_BAR,
	.sram_bar		= NPU3_MBOX_BUFFER_BAR,
	.doorbell_bar		= NPU3_DOORBELL_BAR,
	.default_vbnv		= "RyzenAI-npu9-vf",
	.device_type		= AMDXDNA_DEV_TYPE_UMQ,
	.dev_priv		= &npu3_dev_vf_priv,
	.fw_feature_tbl		= npu3_fw_feature_table,
	.cert_feature_tbl	= npu3_cert_feature_table,
	.ops			= &aie4_vf_ops,
	.luts			= &aie4_error_luts,
	.async_max_status_code	= MAX_AIE4_MSG_STATUS_CODE,
};

const struct amdxdna_dev_info dev_npu9_classic_info = {
	.mbox_bar		= NPU3_MBOX_BAR,
	.sram_bar		= NPU3_MBOX_BUFFER_BAR,
	.psp_bar		= NPU3_PSP_BAR_INDEX,
	.smu_bar		= NPU3_SMU_BAR_INDEX,
	.doorbell_bar		= NPU3_DOORBELL_BAR,
	.default_vbnv		= "RyzenAI-npu9",
	.device_type		= AMDXDNA_DEV_TYPE_UMQ,
	.dev_priv		= &npu3_dev_priv,
	.fw_feature_tbl		= npu3_fw_feature_table,
	.cert_feature_tbl	= npu3_cert_feature_table,
	.ops			= &aie4_classic_ops,
	.luts			= &aie4_error_luts,
	.async_max_status_code	= MAX_AIE4_MSG_STATUS_CODE,
};

const struct amdxdna_dev_info dev_npu11_pf_info = {
	.mbox_bar		= NPU3_MBOX_BAR,
	.sram_bar		= NPU3_MBOX_BUFFER_BAR,
	.psp_bar		= NPU3_PSP_BAR_INDEX,
	.smu_bar		= NPU3_SMU_BAR_INDEX,
	.default_vbnv		= "RyzenAI-npu11-pf",
	.device_type		= AMDXDNA_DEV_TYPE_PF,
	.dev_priv		= &npu3_dev_priv,
	.fw_feature_tbl		= npu3_fw_feature_table,
	.cert_feature_tbl	= npu3_cert_feature_table,
	.ops			= &aie4_pf_ops,
	.luts			= &aie4_error_luts,
	.async_max_status_code	= MAX_AIE4_MSG_STATUS_CODE,
};

const struct amdxdna_dev_info dev_npu11_vf_info = {
	.mbox_bar		= NPU3_MBOX_BAR,
	.sram_bar		= NPU3_MBOX_BUFFER_BAR,
	.doorbell_bar		= NPU3_DOORBELL_BAR,
	.default_vbnv		= "RyzenAI-npu11-vf",
	.device_type		= AMDXDNA_DEV_TYPE_UMQ,
	.dev_priv		= &npu3_dev_vf_priv,
	.fw_feature_tbl		= npu3_fw_feature_table,
	.cert_feature_tbl	= npu3_cert_feature_table,
	.ops			= &aie4_vf_ops,
	.luts			= &aie4_error_luts,
	.async_max_status_code	= MAX_AIE4_MSG_STATUS_CODE,
};

const struct amdxdna_dev_info dev_npu11_classic_info = {
	.mbox_bar		= NPU3_MBOX_BAR,
	.sram_bar		= NPU3_MBOX_BUFFER_BAR,
	.psp_bar		= NPU3_PSP_BAR_INDEX,
	.smu_bar		= NPU3_SMU_BAR_INDEX,
	.doorbell_bar		= NPU3_DOORBELL_BAR,
	.default_vbnv		= "RyzenAI-npu11",
	.device_type		= AMDXDNA_DEV_TYPE_UMQ,
	.dev_priv		= &npu3_dev_priv,
	.fw_feature_tbl		= npu3_fw_feature_table,
	.cert_feature_tbl	= npu3_cert_feature_table,
	.ops			= &aie4_classic_ops,
	.luts			= &aie4_error_luts,
	.async_max_status_code	= MAX_AIE4_MSG_STATUS_CODE,
};
