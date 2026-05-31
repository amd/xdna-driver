/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_PLAT_H_
#define _AMDXDNA_PLAT_H_

struct amdxdna_dev;
struct rproc;

enum amdxdna_plat_transport {
	AMDXDNA_TRANSPORT_NONE = 0,
	AMDXDNA_TRANSPORT_RPMSG,
	AMDXDNA_TRANSPORT_SHMEM,
};

/**
 * amdxdna_plat_find_by_rproc - Look up a probed amdxdna platform device
 *                              by its owning remoteproc.
 * @rp: the remoteproc to match against
 *
 * Walks DT nodes matching the amdxdna platform driver's of_match table and
 * returns the &struct amdxdna_dev whose ``amd,remoteproc`` phandle resolves
 * to @rp. The match is restricted to platform devices whose drvdata has
 * already been set by amdxdna_plat_probe(), so callers can use this from
 * within nested probes (e.g. the RPMsg endpoint probe that fires from
 * register_rpmsg_driver()) before driver-core binding completes.
 *
 * Return: pointer to the matching &struct amdxdna_dev, or NULL if no
 *         currently-probed platform device matches @rp.
 */
struct amdxdna_dev *amdxdna_plat_find_by_rproc(struct rproc *rp);

/**
 * amdxdna_plat_register_device - Run the firmware-dependent setup steps
 *                                for a probed amdxdna platform device.
 * @xdna: device returned from amdxdna_plat_find_by_rproc()
 *
 * Performs the steps that require the management transport (RPMsg) channel
 * to be already up:
 *
 *   - dev_info->ops->init(xdna)   (firmware version / metadata queries)
 *   - notifier_wq alloc           (HMM SVM notifier workqueue)
 *   - sysfs_init                  (xdna sysfs attribute group)
 *   - drm_dev_register            (publishes /dev/dri/cardN to userspace)
 *   - pm_runtime_enable + amdxdna_rpm_init
 *
 * Called from the transport's drv_probe (e.g. amdxdna_rpmsg_drv_probe())
 * once the channel has been wired up so management messages can flow.
 * Idempotent: if @xdna is already registered, returns 0.
 *
 * Return: 0 on success, negative errno otherwise.  On failure the
 *         function unwinds any partial state itself.
 */
int amdxdna_plat_register_device(struct amdxdna_dev *xdna);

/**
 * amdxdna_plat_unregister_device - Reverse of amdxdna_plat_register_device()
 * @xdna: previously-registered device
 *
 * Tears down the firmware-dependent state.  Safe to call multiple times
 * and from either drv_remove (channel-down event) or plat_remove
 * (driver unbind) — internal state-tracking ensures each step runs at
 * most once per register_device() call.
 */
void amdxdna_plat_unregister_device(struct amdxdna_dev *xdna);

#endif /* _AMDXDNA_PLAT_H_ */
