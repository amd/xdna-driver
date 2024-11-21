/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AIE2_SOLVER_H
#define _AIE2_SOLVER_H

#include <linux/types.h>

#include "aie2_pci.h"

#define XRS_MAX_COL 128

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
	u32     opc;            /* operations per cycle */
	u32     dma_bw;         /* DMA bandwidth */
};

/*
 * QoS requirement of a resource allocation.
 */
struct aie_qos {
	u32	gops;		/* Giga operations */
	u32	fps;		/* Frames per second */
	u32	dma_bw;		/* DMA bandwidth */
	u32	latency;	/* Frame response latency */
	u32	exec_time;	/* Frame execution time */
	u32	priority;	/* Request priority */
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
	u32                     rid;
	struct aie_part         part;
};

/*
 * Structure used to describe the frequency table.
 * Resource solver chooses the frequency from the table
 * to meet the QOS requirements.
 */
#define POWER_LEVEL_NUM	8

struct clk_list_info {
	u32        num_levels;                     /* available power levels */
	u32        cu_clk_list[POWER_LEVEL_NUM];   /* available aie clock frequencies in Mhz*/
};

struct xrs_action_ops {
	int (*load_hwctx)(struct amdxdna_hwctx *hwctx, struct xrs_action_load *action);
	int (*unload_hwctx)(struct amdxdna_hwctx *hwctx);
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

/*
 * xrsm_init() - Register resource solver. Resource solver client needs
 *              to call this function to register itself.
 *
 * @cfg:	The system metrics for resource solver to use
 *
 * Return:	A resource solver handle
 *
 * Note: We should only create one handle per AIE array to be managed.
 */
void *xrsm_init(struct init_config *cfg);

/*
 * xrs_allocate_resource() - Request to allocate resources for a given context
 *                           and a partition metadata. (See struct part_meta)
 *
 * @hdl:	Resource solver handle obtained from xrs_init()
 * @req:	Input to the Resource solver including request id
 *		and partition metadata.
 * @hwctx:	The given context
 *
 * Return:	0 when successful.
 *		Or standard error number when failing
 *
 * Note:
 *      There is no lock mechanism inside resource solver. So it is
 *      the caller's responsibility to lock down XCLBINs and grab
 *      necessary lock.
 */
int xrs_allocate_resource(void *hdl, struct alloc_requests *req, struct amdxdna_hwctx *hwctx);

/*
 * xrs_release_resource() - Request to free resources for a given context.
 *
 * @hdl:	Resource solver handle obtained from xrs_init()
 * @rid:	The Request ID to identify the requesting context
 */
int xrs_release_resource(void *hdl, u64 rid);
#endif /* _AIE2_SOLVER_H */
