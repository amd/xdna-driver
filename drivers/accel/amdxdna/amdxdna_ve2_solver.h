/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 *
 * VE2 column / partition resource solver for the AUX (Telluride) path.
 * Public entry points use a ve2_* prefix so this file can be linked beside
 * amdxdna_solver.o without duplicate global symbols.
 */

#ifndef _AMDXDNA_VE2_SOLVER_H_
#define _AMDXDNA_VE2_SOLVER_H_

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>

struct drm_device;
struct amdxdna_dev;
struct amdxdna_hwctx;

#include "drm/amdxdna_accel.h"

#define VE2_MIN_COL_SUPPORT		4

struct aie_part {
	u32	start_col;
	u32	ncols;
};

struct aie_qos_cap {
	u32	opc;
	u32	dma_bw;
};

struct aie_qos {
	u32	gops;
	u32	fps;
	u32	dma_bw;
	u32	latency;
	u32	exec_time;
	u32	priority;
	u32	exclusive;
	u32	user_start_col;
};

struct cdo_parts {
	u32			*start_cols;
	u32			cols_len;
	u32			ncols;
	struct aie_qos_cap	qos_cap;
};

struct alloc_requests {
	u64			rid;
	struct cdo_parts	cdo;
	struct aie_qos		rqos;
};

struct xrs_action_load {
	u32		rid;
	struct aie_part	part;
	bool		create_aie_part;
	bool		release_aie_part;
};

#define POWER_LEVEL_NUM		8

struct clk_list_info {
	u32	num_levels;
	u32	cu_clk_list[POWER_LEVEL_NUM];
};

struct xrs_action_ops {
	int (*load)(struct xrs_action_load *action);
	int (*unload)(struct xrs_action_load *action);
};

struct init_config {
	u32			total_col;
	u32			sys_eff_factor;
	u32			latency_adj;
	struct clk_list_info	clk_list;
	struct drm_device	*ddev;
	struct xrs_action_ops	*actions;
};

struct partition_node {
	struct list_head	list;
	u32			nshared;
	u32			start_col;
	u32			ncols;
	bool			exclusive;
};

struct solver_rgroup {
	u32			rgid;
	u32			nnode;
	u32			npartition_node;
	unsigned long		*resbit;
	struct list_head	node_list;
	struct list_head	pt_node_list;
};

struct solver_node {
	struct list_head	list;
	u64			rid;
	struct partition_node	*pt_node;
	u32			dpm_level;
	u32			cols_len;
	u32			start_cols[] __counted_by(cols_len);
};

struct solver_node *ve2_rg_search_node(struct solver_rgroup *rgp, u64 rid);

struct solver_state {
	struct solver_rgroup	rgp;
	struct init_config	cfg;
	struct xrs_action_ops	*actions;
	struct mutex		xrs_lock;/* protect XRS resource allocator */
};

void *ve2_xrsm_init(struct init_config *cfg);
int ve2_xrs_allocate_resource(void *hdl, struct alloc_requests *req,
			      struct xrs_action_load *load_act);
int ve2_xrs_release_resource(void *hdl, u64 rid, struct xrs_action_load *action);
int ve2_xrs_get_total_cols(struct solver_state *xrs);
int ve2_xrs_request(struct amdxdna_dev *xdna, struct amdxdna_hwctx *hwctx);

#endif /* _AMDXDNA_VE2_SOLVER_H_ */
