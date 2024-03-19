/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */
#ifndef _SOLVER_H
#define _SOLVER_H

#include <linux/bitops.h>
#include <linux/bitmap.h>
#include <linux/device.h>

#include "xrs.h"

/*
 * Each partition node contains the information of partition which can be
 * used by multiple CDO groups.
 */
struct partition_node {
	struct list_head	list;
	u32			nshared;	/* # shared requests */
	u32			start_col;	/* start column */
	u32			ncol;		/* # columns */
	bool			exclusive;	/* can not be shared if set */
	struct aie_qos		pqos;		/* QoS Information */
};

/*
 * Each solver node contains the information about CDO group (partition)
 * in a given XCLBIN.
 */
struct solver_node {
	struct list_head	list;
	uuid_t			xclbin_uuid;
	uuid_t			cdo_uuid;
	u64			rid;		/* Request ID from consumer */
	u32			noly;		/* # overlay */
	u32			ncol;		/* # columns */
	u32			*oly;		/* start column array */
	u32			part;		/* selected partition */
	struct aie_qos_cap	qos_cap;	/* CDO group QoS capabilities */
	struct aie_qos		rqos;		/* Requested QoS */

	struct partition_node	*pt_node;
	void			*cb_arg;
};

struct solver_rgroup {
	u32				rgid;
	u32				nnode;
	u32				npartition_node;

	DECLARE_BITMAP(resbit, XRS_MAX_COL);
	struct list_head		node_list;
	struct list_head		pt_node_list;
};

struct solver_state {
	u32				total_col;
	enum xrs_mode			mode;

	struct solver_rgroup		rgp;
	struct init_config		cfg;
	struct xrs_action_ops		*actions;
};
#endif /* _SOLVER_H */
