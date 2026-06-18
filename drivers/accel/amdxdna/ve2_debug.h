/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2026, Advanced Micro Devices, Inc. */

#ifndef _VE2_DEBUG_H_
#define _VE2_DEBUG_H_

struct amdxdna_client;
struct amdxdna_drm_get_array;
struct amdxdna_drm_set_state;

int ve2_debug_get_array(struct amdxdna_client *client, struct amdxdna_drm_get_array *args);
int ve2_set_aie_state(struct amdxdna_client *client, struct amdxdna_drm_set_state *args);

#endif
