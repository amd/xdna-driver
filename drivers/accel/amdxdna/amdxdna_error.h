/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_ERROR_H_
#define _AMDXDNA_ERROR_H_

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/sizes.h>
#include <linux/types.h>

#define AMDXDNA_ERR_DRV_AIE		4
#define AMDXDNA_ERR_SEV_CRITICAL	3
#define AMDXDNA_ERR_CLASS_AIE		2

#define AMDXDNA_ERR_NUM_MASK		GENMASK_U64(15, 0)
#define AMDXDNA_ERR_DRV_MASK		GENMASK_U64(23, 16)
#define AMDXDNA_ERR_SEV_MASK		GENMASK_U64(31, 24)
#define AMDXDNA_ERR_MOD_MASK		GENMASK_U64(39, 32)
#define AMDXDNA_ERR_CLASS_MASK		GENMASK_U64(47, 40)

enum amdxdna_error_num {
	AMDXDNA_ERROR_NUM_AIE_SATURATION = 3,
	AMDXDNA_ERROR_NUM_AIE_FP,
	AMDXDNA_ERROR_NUM_AIE_STREAM,
	AMDXDNA_ERROR_NUM_AIE_ACCESS,
	AMDXDNA_ERROR_NUM_AIE_BUS,
	AMDXDNA_ERROR_NUM_AIE_INSTRUCTION,
	AMDXDNA_ERROR_NUM_AIE_ECC,
	AMDXDNA_ERROR_NUM_AIE_LOCK,
	AMDXDNA_ERROR_NUM_AIE_DMA,
	AMDXDNA_ERROR_NUM_AIE_MEM_PARITY,
	AMDXDNA_ERROR_NUM_KDS_CU = 13,
	AMDXDNA_ERROR_NUM_KDS_EXEC,
	AMDXDNA_ERROR_NUM_UNKNOWN = 15,
};

enum amdxdna_error_module {
	AMDXDNA_ERROR_MODULE_AIE_CORE = 3,
	AMDXDNA_ERROR_MODULE_AIE_MEMORY,
	AMDXDNA_ERROR_MODULE_AIE_SHIM,
	AMDXDNA_ERROR_MODULE_AIE_NOC,
	AMDXDNA_ERROR_MODULE_AIE_PL,
	AMDXDNA_ERROR_MODULE_UNKNOWN = 8,
};

#define AMDXDNA_ERROR_ENCODE(err_num, err_mod)				\
	(FIELD_PREP(AMDXDNA_ERR_NUM_MASK, err_num) |			\
	 FIELD_PREP_CONST(AMDXDNA_ERR_DRV_MASK, AMDXDNA_ERR_DRV_AIE) |	\
	 FIELD_PREP_CONST(AMDXDNA_ERR_SEV_MASK, AMDXDNA_ERR_SEV_CRITICAL) | \
	 FIELD_PREP(AMDXDNA_ERR_MOD_MASK, err_mod) |			\
	 FIELD_PREP_CONST(AMDXDNA_ERR_CLASS_MASK, AMDXDNA_ERR_CLASS_AIE))

#define AMDXDNA_EXTRA_ERR_COL_MASK	GENMASK_U64(7, 0)
#define AMDXDNA_EXTRA_ERR_ROW_MASK	GENMASK_U64(15, 8)

#define AMDXDNA_EXTRA_ERR_ENCODE(row, col)				\
	(FIELD_PREP(AMDXDNA_EXTRA_ERR_COL_MASK, col) |			\
	 FIELD_PREP(AMDXDNA_EXTRA_ERR_ROW_MASK, row))

#define AMDXDNA_EXTRA_ERR_CTX_ID_MASK		GENMASK_U64(31, 0)
#define AMDXDNA_EXTRA_ERR_CTX_STATUS_MASK	GENMASK_U64(63, 32)

#define AMDXDNA_EXTRA_ERR_CTX_ENCODE(status, ctx_id)			\
	(FIELD_PREP(AMDXDNA_EXTRA_ERR_CTX_ID_MASK, ctx_id) |		\
	 FIELD_PREP(AMDXDNA_EXTRA_ERR_CTX_STATUS_MASK, status))

/*
 * Shared asynchronous error framework used by both the aie2 and aie4 back ends.
 *
 * The genuinely-common scaffolding lives in amdxdna_error.c: the async event
 * buffer pool (alloc, free, mailbox callback, re-register worker), the column
 * backtrack and last-error encode, and the GET_ARRAY query. The device specific
 * pieces come from the device tables: the register-event and handle-event
 * callbacks in struct amdxdna_dev_ops, and the MAX status code and the
 * per-generation AIE tile-error categorization tables (luts) in
 * struct amdxdna_dev_info.
 */

/* Per-event async report buffer size. Shared by aie2 and aie4 firmware. */
#define ASYNC_BUF_SIZE		SZ_8K

struct aie_device;
struct amdxdna_async_error;
struct amdxdna_async_events;
struct amdxdna_drm_get_array;

/*
 * AIE module type and error category. These enums are common to all AIE
 * generations; only the event_id lookup tables that map to them are per-arch
 * (see the aie2 / aie4 event-category tables in aie2_error.c / aie4_error.c).
 */
enum aie_module_type {
	AIE_MEM_MOD = 0,
	AIE_CORE_MOD,
	AIE_PL_MOD,
	AIE_UNKNOWN_MOD,
};

enum aie_error_category {
	AIE_ERROR_SATURATION = 0,
	AIE_ERROR_FP,
	AIE_ERROR_STREAM,
	AIE_ERROR_ACCESS,
	AIE_ERROR_BUS,
	AIE_ERROR_INSTRUCTION,
	AIE_ERROR_ECC,
	AIE_ERROR_LOCK,
	AIE_ERROR_DMA,
	AIE_ERROR_MEM_PARITY,
	/* Unknown is not a hardware category, added for better categorization */
	AIE_ERROR_UNKNOWN,
};

/**
 * struct aie_error_event - one AIE tile error event lookup entry
 * @event_id: hardware event id.
 * @category: error category the event belongs to.
 * @name: human-readable event name for logging.
 *
 * The per-arch tables are arrays of these entries.
 */
struct aie_error_event {
	u8			event_id;
	enum aie_error_category	category;
	const char		*name;
};

#define AIE_ERROR_EVENT(id, cat, nm) \
	{ .event_id = (id), .category = (cat), .name = (nm) }

/**
 * struct aie_error_lut_set - per-arch set of module event-category tables
 * @shim: table for AIE_PL_MOD (shim tile).
 * @core: table for AIE_CORE_MOD.
 * @mem_tile: table for AIE_MEM_MOD when the row falls within the firmware
 *            provided mem-tile row range (a dedicated mem tile).
 * @mem: table for AIE_MEM_MOD otherwise (the core-tile memory module).
 *
 * Each table is terminated by a sentinel entry with a NULL @name.
 */
struct aie_error_lut_set {
	const struct aie_error_event	*shim;
	const struct aie_error_event	*core;
	const struct aie_error_event	*mem_tile;
	const struct aie_error_event	*mem;
};

/*
 * Shared module-dispatch + lookup for the per-arch event-category tables. Sets
 * *name (default "unknown"), selects the table by module (and row for MEM),
 * runs the match loop, and returns the error category.
 */
enum aie_error_category
aie_lookup_error_category(struct aie_device *aie,
			  u8 row, u8 event_id, u32 mod_type, const char **name);

/**
 * struct amdxdna_aie_err_decode - one decoded AIE tile error
 * @err_num: driver error number (enum amdxdna_error_num).
 * @err_mod: driver error module (enum amdxdna_error_module).
 * @mod_str: human-readable AIE module name for logging.
 * @cat_str: human-readable error category name for logging.
 * @event_str: human-readable event name for logging.
 *
 * The event_id to category mapping is specific to the AIE generation, so the
 * tables (luts) that produce this decode live on the aie2 / aie4 side, not in
 * the shared core.
 */
struct amdxdna_aie_err_decode {
	enum amdxdna_error_num		err_num;
	enum amdxdna_error_module	err_mod;
	const char			*mod_str;
	const char			*cat_str;
	const char			*event_str;
};

/*
 * Fill the generic (arch-independent) parts of a decode: the driver error
 * number / module and the human-readable module, category and event strings.
 * The shared backtrack code calls this after looking up the category and event
 * name in the per-arch tables (via ops->luts).
 */
void amdxdna_aie_fill_decode(enum aie_error_category cat, u32 mod_type,
			     const char *event_name,
			     struct amdxdna_aie_err_decode *out);

int amdxdna_async_events_alloc(struct aie_device *aie, u32 total_col);
void amdxdna_async_events_free(struct aie_device *aie);
int amdxdna_get_array_last_async_error(struct aie_device *aie,
				       struct amdxdna_drm_get_array *args);

#endif /* _AMDXDNA_ERROR_H_ */
