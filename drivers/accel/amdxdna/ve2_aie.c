// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * VE2-private adapter for the Linux Xilinx AIE partition API. This is the
 * only VE2 translation unit that may include xlnx-ai-engine.h or call aie_*.
 */

#include <linux/err.h>
#include <linux/slab.h>
#include <linux/xlnx-ai-engine.h>

#include "ve2_aie.h"

static u32 ve2_aie_init_options(enum ve2_aie_init_mode mode)
{
	switch (mode) {
	case VE2_AIE_INIT_FIRMWARE:
		return (AIE_PART_INIT_OPT_DEFAULT | AIE_PART_INIT_OPT_DIS_TLAST_ERROR) &
		       ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;
	case VE2_AIE_INIT_RUNTIME:
		return (AIE_PART_INIT_OPT_DEFAULT | AIE_PART_INIT_OPT_HANDSHAKE |
			AIE_PART_INIT_OPT_DIS_TLAST_ERROR) &
		       ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;
	case VE2_AIE_INIT_RUNTIME_PERF:
		return AIE_PART_INIT_OPT_COLUMN_RST | AIE_PART_INIT_OPT_SHIM_RST |
		       AIE_PART_INIT_OPT_ISOLATE | AIE_PART_INIT_OPT_SET_L2_IRQ |
		       AIE_PART_INIT_OPT_NMU_CONFIG | AIE_PART_INIT_OPT_DIS_TLAST_ERROR |
		       AIE_PART_INIT_OPT_USER_EVENT1_INIT | AIE_PART_INIT_OPT_HANDSHAKE;
	default:
		return 0;
	}
}

static struct aie_op_handshake_data *
ve2_aie_pack_handshake(const struct ve2_aie_handshake *handshake, u32 handshake_cols)
{
	struct aie_op_handshake_data *aie_handshake;
	u32 col;

	if (!handshake_cols)
		return NULL;
	if (!handshake)
		return ERR_PTR(-EINVAL);

	aie_handshake = kmalloc_array(handshake_cols, sizeof(*aie_handshake), GFP_KERNEL);
	if (!aie_handshake)
		return ERR_PTR(-ENOMEM);

	for (col = 0; col < handshake_cols; col++) {
		aie_handshake[col].addr = handshake[col].addr;
		aie_handshake[col].dma_addr = handshake[col].dma_addr;
		aie_handshake[col].size = handshake[col].size;
		aie_handshake[col].offset = handshake[col].offset;
		aie_handshake[col].loc.col = handshake[col].col;
		aie_handshake[col].loc.row = handshake[col].row;
	}

	return aie_handshake;
}

int ve2_aie_get_device_info(struct ve2_aie_device_info *info)
{
	struct aie_device_info aie_info;
	int ret;

	if (!info)
		return -EINVAL;

	ret = aie_get_device_info(&aie_info);
	if (ret)
		return ret;

	info->cols = aie_info.cols;
	info->rows = aie_info.rows;
	info->core_rows = aie_info.core_rows;
	info->mem_rows = aie_info.mem_rows;
	info->shim_rows = aie_info.shim_rows;
	return 0;
}

struct device *ve2_aie_partition_request(u32 start_col, u32 num_col,
					 ve2_aie_event_cb_fn event_cb,
					 void *event_priv, u32 *partition_id)
{
	struct aie_partition_req req = { };
	struct device *aie_dev;

	if (num_col)
		req.partition_id = (start_col << AIE_PART_ID_START_COL_SHIFT) |
				   (num_col << AIE_PART_ID_NUM_COLS_SHIFT);
	req.user_event1_complete = event_cb;
	req.user_event1_priv = event_priv;

	aie_dev = aie_partition_request(&req);
	if (!IS_ERR(aie_dev) && partition_id)
		*partition_id = req.partition_id;

	return aie_dev;
}

void ve2_aie_partition_release(struct device *aie_dev)
{
	aie_partition_release(aie_dev);
}

int ve2_aie_partition_teardown(struct device *aie_dev)
{
	return aie_partition_teardown(aie_dev);
}

int ve2_aie_partition_initialize(struct device *aie_dev, enum ve2_aie_init_mode mode,
				 const struct ve2_aie_handshake *handshake,
				 u32 handshake_cols)
{
	struct aie_op_handshake_data *aie_handshake;
	struct aie_partition_init_args args = { };
	u32 init_opts;
	int ret;

	init_opts = ve2_aie_init_options(mode);
	if (!init_opts)
		return -EINVAL;

	aie_handshake = ve2_aie_pack_handshake(handshake, handshake_cols);
	if (IS_ERR(aie_handshake))
		return PTR_ERR(aie_handshake);

	args.init_opts = init_opts;
	args.handshake = aie_handshake;
	args.handshake_cols = handshake_cols;
	ret = aie_partition_initialize(aie_dev, &args);
	kfree(aie_handshake);

	return ret;
}

int ve2_aie_partition_handshake_update(struct device *aie_dev,
				       const struct ve2_aie_handshake *handshake,
				       u32 handshake_cols)
{
	struct aie_op_handshake_data *aie_handshake;
	int ret;

	aie_handshake = ve2_aie_pack_handshake(handshake, handshake_cols);
	if (IS_ERR(aie_handshake))
		return PTR_ERR(aie_handshake);

	ret = aie_partition_handshake_update(aie_dev, aie_handshake, handshake_cols);
	kfree(aie_handshake);

	return ret;
}

int ve2_aie_partition_wake_lead_uc(struct device *aie_dev)
{
	struct aie_location lead = { .col = 0, .row = 0 };

	return aie_partition_uc_wakeup(aie_dev, &lead);
}

int ve2_aie_load_cert(struct device *aie_dev, void *data)
{
	return aie_load_cert_broadcast(aie_dev, data);
}

int ve2_aie_read(struct device *aie_dev, u32 col, u32 row, size_t offset,
		 size_t size, void *buf)
{
	struct aie_location loc = { .col = col, .row = row };

	return aie_partition_read(aie_dev, loc, offset, size, buf);
}

int ve2_aie_write(struct device *aie_dev, u32 col, u32 row, size_t offset,
		  size_t size, void *buf)
{
	struct aie_location loc = { .col = col, .row = row };

	return aie_partition_write(aie_dev, loc, offset, size, buf, 0);
}

int ve2_aie_priv_read(struct device *aie_dev, size_t offset, size_t size, void *buf)
{
	return aie_partition_read_privileged_mem(aie_dev, offset, size, buf);
}

int ve2_aie_priv_write(struct device *aie_dev, size_t offset, size_t size, void *buf)
{
	return aie_partition_write_privileged_mem(aie_dev, offset, size, buf);
}

int ve2_aie_coredump(struct device *aie_dev, size_t size, void *buf)
{
	return aie_partition_coredump(aie_dev, size, buf);
}

int ve2_aie_get_freq(struct device *aie_dev, u64 *freq)
{
	return aie_partition_get_freq(aie_dev, freq);
}

int ve2_aie_set_freq(struct device *aie_dev, u64 freq)
{
	return aie_partition_set_freq_req(aie_dev, freq);
}

int ve2_aie_get_fd(struct device *aie_dev)
{
	return aie_partition_get_fd(aie_dev);
}

int ve2_aie_register_error_cb(struct device *aie_dev, ve2_aie_error_cb_fn cb, void *priv)
{
	return aie_register_error_notification(aie_dev, cb, priv);
}

int ve2_aie_unregister_error_cb(struct device *aie_dev)
{
	return aie_unregister_error_notification(aie_dev);
}

struct ve2_aie_errors *ve2_aie_get_errors(struct device *aie_dev)
{
	struct ve2_aie_errors *errors;
	struct aie_errors *aie_errors;
	u32 i;

	aie_errors = aie_get_errors(aie_dev);
	if (IS_ERR(aie_errors))
		return ERR_CAST(aie_errors);
	if (!aie_errors)
		return ERR_PTR(-ENODATA);

	errors = kzalloc(struct_size(errors, errors, aie_errors->num_err), GFP_KERNEL);
	if (!errors) {
		aie_free_errors(aie_errors);
		return ERR_PTR(-ENOMEM);
	}

	errors->num_err = aie_errors->num_err;
	for (i = 0; i < errors->num_err; i++) {
		errors->errors[i].category = aie_errors->errors[i].category;
		errors->errors[i].module = aie_errors->errors[i].module;
		errors->errors[i].error_id = aie_errors->errors[i].error_id;
		errors->errors[i].col = aie_errors->errors[i].loc.col;
		errors->errors[i].row = aie_errors->errors[i].loc.row;
	}
	aie_free_errors(aie_errors);

	return errors;
}

void ve2_aie_free_errors(struct ve2_aie_errors *errors)
{
	kfree(errors);
}
