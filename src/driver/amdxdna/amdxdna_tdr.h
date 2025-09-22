/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_TDR_H_
#define _AMDXDNA_TDR_H_

#include <linux/list.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#define to_tdr(work) \
	((struct amdxdna_tdr *)container_of(work, struct amdxdna_tdr, tdr_work))

struct amdxdna_tdr {
	struct timer_list	timer;
	struct work_struct	tdr_work;
	int			tdr_counter;
	int			started;
	u32			progress;
};

void amdxdna_tdr_start(struct amdxdna_tdr *tdr);
void amdxdna_tdr_stop(struct amdxdna_tdr *tdr);

#endif /* _AMDXDNA_TDR_H_ */
