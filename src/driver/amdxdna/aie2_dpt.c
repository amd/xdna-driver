// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include "aie2_pci.h"
#include "aie2_msg_priv.h"
#include "amdxdna_mgmt.h"

#define AIE2_MGMT_APP_ID		0xFF

static const char * const fw_log_level_str[] = {
	"OFF",
	"ERR",
	"WRN",
	"INF",
	"DBG",
	"MAX"
};

struct fw_log_header {
#define AIE2_DPT_ENTRY_MAGIC_HEAD	0xCA
	u8 magic;
	u8 data_word_len;
	u16 seq_num;
	u32 reserved;
} __packed;

struct fw_log_data {
	u64 timestamp;
	u32 format      : 1;
	u32 reserved_1  : 7;
	u32 level       : 3;
	u32 reserved_11 : 5;
	u32 appn        : 8;
	u32 argc        : 8;
	u32 line        : 16;
	u32 module      : 16;
} __packed;

struct fw_log_footer {
	u32 reserved;
	u16 seq_num;
	u8 data_word_len;
#define AIE2_DPT_ENTRY_MAGIC_FOOTER	0xBA
	u8 magic;
} __packed;

static
void aie2_dpt_parse(struct amdxdna_dev *xdna, char *buffer, size_t size,
		    void (*print)(struct amdxdna_dev *xdna, const char *payload, size_t size))
{
	char *end = buffer + size;
	bool has_prev_seq = false;
	char *p = buffer;
	u16 prev_seq = 0;

	if (!print)
		return;

	while ((size_t)(end - p) >= sizeof(struct fw_log_header)) {
		unsigned int increment_bytes = 4; /* default scan step (min alignment) */
		bool corrupted = true;

		const struct fw_log_header *hdr = (const struct fw_log_header *)p;

		/* Fast path */
		if (likely(hdr->magic == AIE2_DPT_ENTRY_MAGIC_HEAD)) {
			u16 seq = hdr->seq_num;
			size_t payload_bytes = hdr->data_word_len * sizeof(u64);
			size_t total_entry_size = sizeof(struct fw_log_header) +
						  payload_bytes +
						  sizeof(struct fw_log_footer);

			/* Partial entry at end: stop to avoid overread */
			if ((size_t)(end - p) < total_entry_size)
				break;

			const char *payload = p + sizeof(struct fw_log_header);
			const struct fw_log_footer *ftr = (const struct fw_log_footer *)
				(payload + payload_bytes);
			bool valid = (ftr->magic == AIE2_DPT_ENTRY_MAGIC_FOOTER) &&
				     (seq > 0) && (seq == ftr->seq_num) &&
				     (hdr->data_word_len == ftr->data_word_len);

			if (likely(valid)) {
				if (likely(!has_prev_seq || (seq == (u16)(prev_seq + 1)))) {
					has_prev_seq = true;
					prev_seq = seq;

					print(xdna, payload, payload_bytes);
					corrupted = false;
					increment_bytes = (unsigned int)total_entry_size;
				}
			}

			if (unlikely(corrupted)) {
				XDNA_WARN(xdna, "Entry overwritten/corrupted");
				has_prev_seq = false;
			}
		}

		/* Advance by increment_bytes safely */
		if (unlikely(increment_bytes == 0) || (size_t)(end - p) < increment_bytes)
			break;

		p += increment_bytes;
	}
}

static void aie2_fw_log_print(struct amdxdna_dev *xdna, const char *payload, size_t size)
{
	struct fw_log_data *data = (struct fw_log_data *)payload;
	const char *level_str;
	char appid[20];

	if (size < sizeof(struct fw_log_data))
		return;

	if (data->level < ARRAY_SIZE(fw_log_level_str))
		level_str = fw_log_level_str[data->level];
	else
		level_str = "UNK";

	if (data->appn == AIE2_MGMT_APP_ID)
		scnprintf(appid, sizeof(appid), "MGMNT");
	else
		scnprintf(appid, sizeof(appid), "APP%2d", data->appn);

	XDNA_INFO(xdna, "[%lld] [%s] [%s]: %.*s", data->timestamp, level_str,
		  appid, (int)(size - sizeof(struct fw_log_data)),
		  (char *)(payload + sizeof(struct fw_log_data)));
}

void aie2_fw_log_parse(struct amdxdna_dev *xdna, char *buffer, size_t size)
{
	return aie2_dpt_parse(xdna, buffer, size, aie2_fw_log_print);
}

int aie2_fw_log_init(struct amdxdna_dev *xdna, size_t size, u8 level)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl = xdna->fw_log->dma_hdl;
	u32 msi_idx, msi_address;
	int ret;

	if (level >= MAX_FW_LOG_LEVEL) {
		XDNA_ERR(xdna,  "Invalid firmware log level: %d", level);
		return -EINVAL;
	}

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_config_fw_log(xdna->dev_handle, dma_hdl, size, &msi_idx, &msi_address);
	if (ret) {
		/* Sliently fail for device generation that don't support FW logging */
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to init fw log buffer: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}

	ret = aie2_set_log_level(xdna->dev_handle, level);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log level: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}

	ret = aie2_set_log_format(xdna->dev_handle, FW_LOG_FORMAT_FULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log format: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}

	ret = aie2_set_log_destination(xdna->dev_handle, FW_LOG_DESTINATION_DRAM);
	if (ret) {
		XDNA_ERR(xdna, "Failed to init fw log destination: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);

	xdna->fw_log->io_base = xdna->dev_handle->mbox_base;
	xdna->fw_log->msi_address = msi_address & AIE2_DPT_MSI_ADDR_MASK;
	xdna->fw_log->msi_idx = msi_idx;

	return ret;
}

int aie2_fw_log_config(struct amdxdna_dev *xdna, u8 level)
{
	int ret;

	if (level == FW_LOG_LEVEL_NONE || level >= MAX_FW_LOG_LEVEL) {
		XDNA_ERR(xdna,  "Invalid firmware log level: %d", level);
		return -EINVAL;
	}

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_set_log_level(xdna->dev_handle, level);
	if (ret)
		XDNA_ERR(xdna, "Failed to init fw log level: %d", ret);
	mutex_unlock(&xdna->dev_handle->aie2_lock);

	return ret;
}

int aie2_fw_log_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl = xdna->fw_log->dma_hdl;
	int ret;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_set_log_destination(xdna->dev_handle, FW_LOG_DESTINATION_FIXED);
	if (ret) {
		/* Sliently fail for device generation that don't support FW logging */
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to reset fw log destination: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}

	ret = aie2_config_fw_log(xdna->dev_handle, dma_hdl, 0, NULL, NULL);
	if (ret) {
		XDNA_ERR(xdna, "Failed to reset fw log buffer: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);
	return 0;
}

static void aie2_fw_trace_print(struct amdxdna_dev *xdna, const char *buffer, size_t size)
{
	if (!size)
		return;

	print_hex_dump(KERN_INFO, "[FW TRACE]: ", DUMP_PREFIX_OFFSET, 16, 4, buffer, size, false);
}

void aie2_fw_trace_parse(struct amdxdna_dev *xdna, char *buffer, size_t size)
{
	return aie2_dpt_parse(xdna, buffer, size, aie2_fw_trace_print);
}

int aie2_fw_trace_init(struct amdxdna_dev *xdna, size_t size, u32 categories)
{
	struct amdxdna_mgmt_dma_hdl *dma_hdl = xdna->fw_trace->dma_hdl;
	u32 msi_idx, msi_address;
	int ret;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_start_fw_trace(xdna->dev_handle, dma_hdl, size, categories, &msi_idx,
				  &msi_address);
	if (ret) {
		/* Sliently fail for device generation that don't support FW tracing */
		if (ret != -EOPNOTSUPP)
			XDNA_ERR(xdna, "Failed to init fw trace buffer: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);

	xdna->fw_trace->io_base = xdna->dev_handle->mbox_base;
	xdna->fw_trace->msi_address = msi_address & AIE2_DPT_MSI_ADDR_MASK;
	xdna->fw_trace->msi_idx = msi_idx;

	return ret;
}

int aie2_fw_trace_config(struct amdxdna_dev *xdna, u32 categories)
{
	int ret;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_set_trace_categories(xdna->dev_handle, categories);
	if (ret)
		XDNA_ERR(xdna, "Failed to init fw trace categories: %d", ret);
	mutex_unlock(&xdna->dev_handle->aie2_lock);

	return ret;
}

int aie2_fw_trace_fini(struct amdxdna_dev *xdna)
{
	int ret;

	mutex_lock(&xdna->dev_handle->aie2_lock);
	ret = aie2_stop_fw_trace(xdna->dev_handle);
	if (ret) {
		XDNA_ERR(xdna, "Failed to stop fw trace: %d", ret);
		mutex_unlock(&xdna->dev_handle->aie2_lock);
		return ret;
	}
	mutex_unlock(&xdna->dev_handle->aie2_lock);
	return 0;
}
