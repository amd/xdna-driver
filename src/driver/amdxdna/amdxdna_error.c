// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include "amdxdna_error.h"
#include "drm_local/amdxdna_accel.h"

/**
 * amdxdna_error_async_cache_init - Initialize async error cache
 * @err_cache: error cache pointer to initialize
 * Return: 0 for success.
 */
int amdxdna_error_async_cache_init(struct amdxdna_async_err_cache *err_cache)
{
	mutex_init(&err_cache->lock);
	return 0;
}

/**
 * amdxdna_aie2_get_last_async_error - Retrieve the last asynchronous error information.
 * @xdna: Pointer to the xdna structure, it is used when printing function related information
 * @err_cache: async errors cache
 * @num_errs: Number of error structures to populate.
 * @errors: errors array for returning errors information.
 *
 * This function obtains the most recent asynchronous error that occurred
 * in the xdna subsystem and populates the provided error information structure.
 * It is typically used for error handling and diagnostics in the driver.
 * Today, only one last async error is cached. And thus, this function will only
 * return 1 last async error.
 *
 * Return: 0 on success, negative error code on failure.
 */
int amdxdna_error_get_last_async(struct amdxdna_dev *xdna,
				 struct amdxdna_async_err_cache *err_cache, u32 num_errs,
				 void *errors)
{
	struct amdxdna_async_error *cached_last_err = &err_cache->err;

	if (num_errs == 0 || !errors) {
		XDNA_ERR(xdna,
			 "get last async failed due to invalid input num_errors or empty errors array.");
		return -EINVAL;
	}

	/* Retrieve the last async error information */
	mutex_lock(&err_cache->lock);
	if (!cached_last_err->err_code) {
		mutex_unlock(&err_cache->lock);
		return 0;
	}

	memcpy(errors, cached_last_err, sizeof(*cached_last_err));
	mutex_unlock(&err_cache->lock);

	return 1;
}
