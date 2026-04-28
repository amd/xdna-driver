/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_RPMSG_H_
#define _AMDXDNA_RPMSG_H_

struct amdxdna_dev;

/*
 * Module-level (un)registration of the internal rpmsg endpoint driver.
 *
 * Called once from amdxdna_plat.c's module_init/module_exit, AFTER the
 * platform_driver has been registered (and BEFORE it is unregistered).
 * Doing it in this order means by the time the rpmsg core starts
 * dispatching channel announcements to drv_probe(), at least one
 * matching plat_probe has run and amdxdna_plat_find_by_rproc() can find
 * a probed xdna.  If a channel happens to be announced before that,
 * drv_probe() returns -EPROBE_DEFER and resets rpdev->src so the
 * deferred-probe machinery can retry cleanly when the plat device
 * eventually probes.
 */
int amdxdna_rpmsg_drv_register(void);
void amdxdna_rpmsg_drv_unregister(void);

/*
 * Per-platform-device transport setup/teardown.
 *
 * amdxdna_rpmsg_init() allocates the per-device rpmsg state (rhdl) and
 * installs xcomm_ops/xcomm_hdl on ndev so management code can route
 * messages over the channel.  It does NOT block on rproc readiness or
 * channel announcement: rhdl->rpdev may still be NULL on return.
 * Senders gracefully return -ENODEV in that window and are wired up
 * automatically by drv_probe() once the rpmsg core dispatches the
 * "rpmsg-aie-mgmt" channel to this driver.
 *
 * amdxdna_rpmsg_fini() detaches this xdna's specific rpdev (if still
 * bound) via device_release_driver() so a peer AIE device's binding is
 * not disturbed, then frees rhdl bookkeeping.
 */
int amdxdna_rpmsg_init(struct amdxdna_dev *xdna);
void amdxdna_rpmsg_fini(struct amdxdna_dev *xdna);

#endif /* _AMDXDNA_RPMSG_H_ */
