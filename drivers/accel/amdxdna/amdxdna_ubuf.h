/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026, Advanced Micro Devices, Inc.
 */
#ifndef _AMDXDNA_UBUF_H_
#define _AMDXDNA_UBUF_H_

#include "amdxdna_gem.h"
#include "amdxdna_pci_drv.h"

struct amdxdna_gem_obj *amdxdna_alloc_ubuf_bo(struct amdxdna_client *client,
					      u32 num_entries, void __user *va_entries);

#endif /* _AMDXDNA_UBUF_H_ */
