/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_SOLVER_H
#define _AMDXDNA_SOLVER_H

#include <linux/mutex.h>
#include <linux/types.h>

#define XRS_MAX_COL		(128)
#define DEFAULT_SYS_EFF_FACTOR	(2)

/*
 * Structure used to describe a partition. A partition is column based
 * allocation unit described by its start column and number of columns.
 */
struct aie_part {
	u32	start_col;
	u32	ncols;
};

/*
 * The QoS capabilities of a given AIE partition.
 */
struct aie_qos_cap {
	u32	opc;		/* operations per cycle */
	u32	dma_bw;		/* DMA bandwidth */
};

/*
 * QoS requirement of a resource allocation.
 */
#define USER_START_COL_NOT_REQUESTED	0xFF

struct aie_qos {
	u32	gops;		/* Giga operations */
	u32	fps;		/* Frames per second */
	u32	dma_bw;		/* DMA bandwidth */
	u32	latency;	/* Frame response latency */
	u32	exec_time;	/* Frame execution time */
	u32	priority;	/* Request priority */
	u32	exclusive;	/* Exclusive partition */
	u32	user_start_col;	/* Preferred start column, or USER_START_COL_NOT_REQUESTED */
};

/*
 * Structure used to describe a relocatable CDO (Configuration Data Object).
 */
struct cdo_parts {
	u32		   *start_cols;		/* Start column array */
	u32		   cols_len;		/* Length of start column array */
	u32		   ncols;		/* # of column */
	struct aie_qos_cap qos_cap;		/* CDO QoS capabilities */
};

/*
 * Structure used to describe a request to allocate.
 */
struct alloc_requests {
	u64			rid;
	struct cdo_parts	cdo;
	struct aie_qos		rqos;		/* Requested QoS */
};

/*
 * Load callback argument
 */
struct xrs_action_load {
	u32			rid;
	struct aie_part		part;
	bool			create_aie_part;
	bool			release_aie_part;
};

/*
 * Define the power level available
 *
 * POWER_LEVEL_MIN:
 *     Lowest power level. Usually set when all actions are unloaded.
 *
 * POWER_LEVEL_n
 *     Power levels 0 - n, is a step increase in system frequencies
 */
enum power_level {
	POWER_LEVEL_MIN = 0x0,
	POWER_LEVEL_0   = 0x1,
	POWER_LEVEL_1   = 0x2,
	POWER_LEVEL_2   = 0x3,
	POWER_LEVEL_3   = 0x4,
	POWER_LEVEL_4   = 0x5,
	POWER_LEVEL_5   = 0x6,
	POWER_LEVEL_6   = 0x7,
	POWER_LEVEL_7   = 0x8,
	POWER_LEVEL_NUM,
};

/*
 * Structure used to describe the frequency table.
 * Resource solver chooses the frequency from the table
 * to meet the QOS requirements.
 */
struct clk_list_info {
	u32	num_levels;	/* available power levels */
	u32	cu_clk_list[POWER_LEVEL_NUM];	/* available aie clock frequencies in Mhz*/
};

struct xrs_action_ops {
	int (*load)(void *cb_arg, struct xrs_action_load *action);
	int (*unload)(void *cb_arg);
	int (*set_dft_dpm_level)(struct drm_device *ddev, u32 level);
};

/*
 * Structure used to describe information for solver during initialization.
 */
struct init_config {
	u32			total_col;
	u32			sys_eff_factor; /* system efficiency factor */
	u32			latency_adj;    /* latency adjustment in ms */
	struct clk_list_info	clk_list;       /* List of frequencies available in system */
	struct drm_device	*ddev;
	struct xrs_action_ops	*actions;
};

struct partition_node {
	struct list_head	list;
	u32			nshared;	/* # shared requests */
	u32			start_col;	/* start column */
	u32			ncols;		/* # columns */
	bool			exclusive;	/* can not be shared if set */
};

struct solver_node {
	struct list_head	list;
	u64			rid;		/* Request ID from consumer */

	struct partition_node	*pt_node;
	void			*cb_arg;
	u32			dpm_level;
	u32			cols_len;
	u32			start_cols[] __counted_by(cols_len);
};

struct solver_rgroup {
	u32				rgid;
	u32				nnode;
	u32				npartition_node;

	unsigned long			*resbit;	/* dynamic bitmap, size = total_col */
	struct list_head		node_list;
	struct list_head		pt_node_list;
};

struct solver_state {
	struct solver_rgroup		rgp;
	struct init_config		cfg;
	struct xrs_action_ops		*actions;
	struct mutex			xrs_lock;	/* serialise alloc/release */
};

/*
 * xrsm_init() - Register resource solver. Resource solver client needs
 *               to call this function to register itself.
 *
 * @cfg:	The system metrics for resource solver to use
 *
 * Return:	A resource solver handle
 *
 * Note: We should only create one handle per AIE array to be managed.
 */
void *xrsm_init(struct init_config *cfg);

/* QoS helper functions shared with power management */
u32 xrs_get_gops(struct aie_qos *rqos);

/*
 * xrs_allocate_resource() - Request to allocate resources for a given context
 *                           and a partition metadata.
 *
 * @hdl:	Resource solver handle obtained from xrs_init()
 * @req:	Input to the Resource solver including request id
 *		and partition metadata.
 * @cb_arg:	callback argument pointer
 * @action:	Action to perform
 *
 * PCI: pass @cb_arg (hwctx), @action NULL — runs load callback and DPM.
 * VE2: pass @action, @cb_arg NULL — column pick only (partition in ve2_aie).
 *
 * Return:	0 when successful.
 *		Or standard error number when failing
 *
 * Note:
 *      There is no lock mechanism inside resource solver. So it is
 *      the caller's responsibility to lock down XCLBINs and grab
 *      necessary lock.
 */
int xrs_allocate_resource(void *hdl, struct alloc_requests *req, void *cb_arg,
			  struct xrs_action_load *action);

/*
 * xrs_release_resource() - Request to free resources for a given context.
 *
 * @hdl:	Resource solver handle obtained from xrs_init()
 * @rid:	The Request ID to identify the requesting context
 * @action:	Action to perform
 *
 * PCI: runs unload callback. VE2: bitmap/node teardown only (@action unused).
 */
int xrs_release_resource(void *hdl, u64 rid, struct xrs_action_load *action);

/*
 * amdxdna_alloc_resource() - Allocate AIE resources for a hardware context
 *
 * @hwctx:	Hardware context pointer
 *
 * PCI: uses col_list, QoS, mailbox load callback, and DPM.
 * VE2: uses num_tiles; column placement only (partition in ve2_aie).
 *
 * Return:	0 when successful, or standard error number when failing
 */
int amdxdna_alloc_resource(struct amdxdna_hwctx *hwctx, bool *create_aie_part);

/*
 * amdxdna_release_resource() - Release AIE resources for a hardware context
 *
 * @hwctx:	Hardware context pointer
 */
void amdxdna_release_resource(struct amdxdna_hwctx *hwctx, bool *release_aie_part);

#endif /* _AMDXDNA_SOLVER_H */

