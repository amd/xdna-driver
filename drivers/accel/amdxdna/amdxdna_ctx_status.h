/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */
#ifndef _AMDXDNA_CTX_STATUS_H_
#define _AMDXDNA_CTX_STATUS_H_

struct aie_device;
struct amdxdna_client;
struct amdxdna_drm_get_info;
struct amdxdna_drm_get_array;

int amdxdna_get_hwctx_status(struct aie_device *aie, struct amdxdna_client *client,
			     struct amdxdna_drm_get_info *args);
int amdxdna_query_ctx_status_array(struct aie_device *aie, struct amdxdna_client *client,
				   struct amdxdna_drm_get_array *args);
int amdxdna_query_ctx_status_by_id(struct aie_device *aie, struct amdxdna_client *client,
				   struct amdxdna_drm_get_array *args);

#endif /* _AMDXDNA_CTX_STATUS_H_ */
