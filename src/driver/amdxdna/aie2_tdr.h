/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#ifndef _AIE2_TDR_H_
#define _AIE2_TDR_H_

#include <linux/list.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

struct aie2_tdr {
	struct timer_list	timer;
	struct work_struct	work;
	int			counter;
	u32			status;
	int			started;
	u32			progress;
};

extern uint timeout_in_sec;

#endif /* _AIE2_TDR_H_ */
