/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _VE2_SOLVER_H_
#define _VE2_SOLVER_H_

#include <linux/types.h>

#include "ve2_of.h"

#define XRS_MAX_COL	36

/*
 * Structure used to describe a partition. A partition is column based
 * allocation unit described by its start column and number of columns.
 */
struct aie_part {
	u32		start_col;
	u32		ncols;
};

/*
 * The QoS capabilities of a given AIE partition.
 */
struct aie_qos_cap {
	u32		opc;	/* operations per cycle */
	u32		dma_bw;	/* DMA bandwidth */
};

/*
 * QoS requirement of a resource allocation.
 */
struct aie_qos {
	u32		gops;		/* Giga operations */
	u32		fps;		/* Frames per second */
	u32		dma_bw;		/* DMA bandwidth */
	u32		latency;	/* Frame response latency */
	u32		exec_time;	/* Frame execution time */
	u32		priority;	/* Request priority */
};

/*
 * Structure used to describe a relocatable CDO (Configuration Data Object).
 */
struct cdo_parts {
	u32			*start_cols;	/* Start column array */
	u32			cols_len;	/* Length of start column array */
	u32			ncols;		/* # of column */
	struct aie_qos_cap	qos_cap;	/* CDO QoS capabilities */
};

/*
 * Structure used to describe a request to allocate.
 */
struct alloc_requests {
	u64			rid;
	struct cdo_parts	cdo;
	struct aie_qos		rqos;	/* Requested QoS */
};

/*
 * Load callback argument
 */
struct xrs_action_load {
	u32			rid;
	struct aie_part		part;
};

/*
 * Structure used to describe the frequency table.
 * Resource solver chooses the frequency from the table
 * to meet the QOS requirements.
 */
#define POWER_LEVEL_NUM		8

struct clk_list_info {
	u32		num_levels;			/* available power levels */
	u32		cu_clk_list[POWER_LEVEL_NUM];	/* available aie clock frequencies in Mhz*/
};

struct xrs_action_ops {
	int (*load)(struct xrs_action_load *action);
	int (*unload)(struct xrs_action_load *action);
};

/*
 * Structure used to describe information for solver during initialization.
 */
struct init_config {
	u32			total_col;
	u32			sys_eff_factor;	/* system efficiency factor */
	u32			latency_adj;	/* latency adjustment in ms */
	struct clk_list_info	clk_list;	/* List of frequencies available in system */
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
	u32			dpm_level;
	u32			cols_len;
	u32			start_cols[] __counted_by(cols_len);
};

struct solver_rgroup {
	u32			rgid;
	u32			nnode;
	u32			npartition_node;
	DECLARE_BITMAP(resbit, XRS_MAX_COL);
	struct list_head	node_list;
	struct list_head	pt_node_list;
};

struct solver_state {
	struct solver_rgroup	rgp;
	struct init_config	cfg;
	struct xrs_action_ops	*actions;
	struct mutex		xrs_lock;	/* resolver lock */
};

void *xrsm_init(struct init_config *cfg);
int xrs_allocate_resource(void *hdl, struct alloc_requests *req, struct xrs_action_load *load_act);
int xrs_release_resource(void *hdl, u64 rid);

struct solver_node *rg_search_node(struct solver_rgroup *rgp, u64 rid);

int xrs_get_total_cols(struct solver_state *xrs);

#endif /* _VE2_SOLVER_H_ */
