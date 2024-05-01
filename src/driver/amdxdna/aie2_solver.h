/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AIE2_SOLVER_H
#define _AIE2_SOLVER_H

#include <linux/types.h>

#define XRS_MAX_COL 128

/*
 * Define the resource management mode
 *
 * XRS_MODE_SPATIAL_STATIC:
 *     Partitions are shared spatially. They are allocated based on the
 *     column availability. If no available columns meet the requested
 *     overlays, allocation will fail.
 *
 * XRS_MODE_SPATIAL_DYNAMIC:
 *     Partitions are shared spatially. They are allocated based on the
 *     best effort of the current request and allocated requests. Allocated
 *     partitions can be moved around to fit all requests. If no overlays meet
 *     the requests, allocation will fail.
 *
 * XRS_MODE_TEMPORAL_BEST:
 *     Partitions can be shared temporally. Firstly, we try to allocate
 *     partition on unused columns. If no available columns meet the
 *     requested overlays, we will share the already allocated partition
 *     with other request. We will try our best to load balance of requests
 *     on partitions.
 *
 * XRS_MODE_REQUEST_GROUP_TEMPORAL:
 *     Requests can be spatially and temporally shared within the same Request
 *     Group.
 *     Requests inside the same Request Group should be created at the same time
 *     as the contexts on the AIE array. If the allocate request can't be
 *     allocated in the request group, resource solver will allocate a new
 *     Request Group with new rgid.
 *     To run the requests from a different Request Group, the caller has to
 *     destroy all contexts in the current Request Group and create the contexts
 *     in the new Request Group.
 */
enum xrs_mode {
	XRS_MODE_SPATIAL_STATIC		= 0x0,
	XRS_MODE_SPATIAL_DYNAMIC	= 0x1,
	XRS_MODE_TEMPORAL_BEST		= 0x2,
	XRS_MODE_REQUEST_GROUP_TEMPORAL = 0x3,
};

/*
 * Structure used to describe a partition. A partition is column based
 * allocation unit described by its start column and number of columns.
 */
struct aie_part {
	u32	start_col;
	u32	ncols;
};

/*
 * The QoS capabilities of a given AIE partition
 *
 * Note:
 *       1) The original data got from XCLBIN is operations per AIE cycle.
 *       2) We will only honor opc for now. Others are just a place holder
 *          for future use.
 */
struct aie_qos_cap {
	u32     opc;            /* operations per cycle */
	u32     dma_bw;         /* DMA bandwidth */
};

/*
 * QoS structure. This includes factors that define the QoS which will be
 * used to describe
 *   1) the QoS requirement of a resource allocation
 *
 * Note:
 *       1) The original data got from XCLBIN is operations per AIE cycle. It
 *          is the Resource Solver's consumers responsibility to convert it to
 *          Tera Operations per second based on the AIE frequency at run time.
 *       2) We will only honor gops for now. Others are just a place holder
 *          for future use.
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
 * Structure used to describe a relocatable CDO. This CDO can be loaded on multiple
 * partition overlays.
 */
struct cdo_parts {
	u32		   *start_cols;		/* Start column array */
	u32		   cols_len;		/* Length of start column array */
	u32		   ncols;		/* # of column */
	struct aie_qos_cap qos_cap;		/* CDO QoS capabilities */
};

/*
 * Structure used to describe a request to allocate. This is the
 * input to resource solver for a allocation request. And this can
 * be extended to include other inputs for the allocation like QoS
 * and Priority.
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
 * Define the power hint available
 *
 * Each power hint type maps to a soft minimum of power level
 * If the power hint does not change, the caller has to pass POWER_HINT_UNCHANGE
 */
enum xrs_power_hint {
	AC_PERF         = 0x0,
	AC_BAL          = 0x1,
	AC_VSS          = 0x2,
	AC_NINT         = 0x3,
	DC_PERF         = 0x4,
	DC_BAL          = 0x5,
	DC_VSS          = 0x6,
	DC_NINT         = 0x7,
	POWER_HINT_NUM,
	POWER_HINT_UNCHANGE = 0x200,
};

/*
 * Define the power mode
 *
 * Each power mode maps to a pair of power level
 * If the power mode does not change, the caller has to pass POWER_MODE_UNCHANGE
 */
enum xrs_power_mode {
	POWER_MODE_DEFAULT     = 0x0,
	POWER_MODE_USER_LOW    = 0x1,
	POWER_MODE_USER_MEDIUM = 0x2,
	POWER_MODE_USER_HIGH   = 0x3,
	POWER_MODE_NUM,
	POWER_MODE_UNCHANGE     = 0x200,
};

/*
 * Structure used to describe the frequency table.
 * Resource solver chooses the frequency from the table
 * to meet the QOS requirements.
 */
struct clk_list_info {
	u32        num_levels;                     /* available power levels */
	u32        cu_clk_list[POWER_LEVEL_NUM];   /* available aie clock frequencies in Mhz*/
	u32        fw_clk_list[POWER_LEVEL_NUM];   /* available generic clock frequencies in MHz*/
};

struct power_hint_entry {
	u32          type;
	u32          power_level;
};

/*
 * Structure used to describe the power hint to power level mapping.
 * Resource solver chooses the power level based on the power hint
 */
struct power_hint_info {
	u32                     num_entries;          /* available power hint entries */
	struct power_hint_entry map[POWER_HINT_NUM];  /* power hint to power level mapping*/
};

struct xrs_action_ops {
	int (*load)(void *cb_arg, struct xrs_action_load *action);
	int (*unload)(void *cb_arg);
};

/*
 * Structure used to describe information for solver during initialization.
 */
struct init_config {
	u32			total_col;
	enum xrs_mode		mode;
	u32			sys_eff_factor; /* system efficiency factor */
	u32			latency_adj;    /* latency adjustment in ms */
	struct clk_list_info	clk_list;       /* List of frequencies available in system */
	u32			pmf_cap;        /* Flag of PMF capabilities */
	struct power_hint_info	power_hint;     /* Takes the mapping into account if pmf_enable */
	struct device		*dev;
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
 * @cb_arg:	callback argument pointer
 *
 * Return:	0 when successful.
 *		Or standard error number when failing
 *
 * Note:
 *      There is no lock mechanism inside resource solver. So it is
 *      the caller's responsibility to lock down XCLBINs and grab
 *      necessary lock.
 */
int xrs_allocate_resource(void *hdl, struct alloc_requests *req, void *cb_arg);

/*
 * xrs_release_resource() - Request to free resources for a given context.
 *
 * @hdl:	Resource solver handle obtained from xrs_init()
 * @rid:	The Request ID to identify the requesting context
 */
int xrs_release_resource(void *hdl, u64 rid);
#endif /* _AIE2_SOLVER_H */
