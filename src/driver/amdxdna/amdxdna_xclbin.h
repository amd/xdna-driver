/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_XCLBIN_H_
#define _AMDXDNA_XCLBIN_H_

#include <linux/uuid.h>
#include <linux/kref.h>
#include "amdxdna_drv.h"

enum pdi_type {
	PDI_TYPE_PRE,
	PDI_TYPE_PRIMARY,
	PDI_TYPE_POST,
	PDI_TYPE_LITE,
	MAX_PDI_TYPE
};

struct amdxdna_pdi {
	uuid_t			uuid;
	int			id;
	void			*image;
	/* address for firmware access */
	u64			addr;
	u32			size;
	enum pdi_type		type;
	const u64		*dpu_ids;
	u32			num_dpu_ids;
	int			registered;
};

struct amdxdna_partition {
	struct amdxdna_pdi	*pdis;
	u32			num_pdis;
	u32			ncols;
	u32			nparts;
	const u16		*start_cols;
	u32			ops;
};

struct amdxdna_cu {
	char			name[64];
	u32			index;
	u32			func;
	u32			dpu_id;
	u32			pdi_id;
};

struct amdxdna_xclbin {
	struct list_head		entry;
	uuid_t				uuid;
	struct kref			ref;
	struct amdxdna_dev		*xdna;

	struct amdxdna_cu		*cu;
	struct amdxdna_partition	partition;
	u32				num_cus;
};

int amdxdna_xclbin_load(struct amdxdna_dev *xdna, uuid_t *uuid, struct amdxdna_xclbin **xclbin);
void amdxdna_xclbin_unload(struct amdxdna_dev *xdna, struct amdxdna_xclbin *xclbin);
int amdxdna_xclbin_load_by_ptr(struct amdxdna_dev *xdna, const void __user *xclbin_p,
			       struct amdxdna_xclbin **xclbin);

#endif /* _AMDXDNA_XCLBIN_H_ */
