/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */
#ifndef _AMDXDNA_TILE_READ_WRITE_H_
#define _AMDXDNA_TILE_READ_WRITE_H_

struct aie_device;
struct amdxdna_client;
struct amdxdna_drm_get_array;
struct amdxdna_drm_set_state;

int amdxdna_aie_tile_read(struct aie_device *aie,
			  struct amdxdna_client *client,
			  struct amdxdna_drm_get_array *args);
int amdxdna_aie_tile_write(struct aie_device *aie,
			   struct amdxdna_client *client,
			   struct amdxdna_drm_set_state *args);

#endif /* _AMDXDNA_TILE_READ_WRITE_H_ */
