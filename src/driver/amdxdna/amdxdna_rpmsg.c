// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * RPMsg transport layer for amdxdna.
 *
 * Provides the xcomm_ops implementation that sends management messages
 * and doorbell notifications over an RPMsg channel.
 *
 * Lifecycle (inverted control flow)
 * ---------------------------------
 * amdxdna_plat_probe() runs only the channel-independent setup
 * (drm_dev_alloc, ndev alloc, drvdata, xrs, CMA, transport_init) and
 * returns success without waiting for the RPU.  The firmware-dependent
 * second half — ops->init(), notifier_wq, sysfs_init, drm_dev_register,
 * runtime PM — is captured in amdxdna_plat_register_device() (in
 * amdxdna_plat.c) and is invoked from drv_probe() below, after the
 * RPMsg channel is hot.  drv_remove() correspondingly calls
 * amdxdna_plat_unregister_device() before tearing the channel down.
 *
 * The rpmsg endpoint driver itself is registered exactly once per
 * module load (amdxdna_rpmsg_drv_register, called from amdxdna_plat.c's
 * module_init *after* platform_driver_register()).  This ordering
 * guarantees that when the rpmsg core's bus walk fires drv_probe(),
 * at least one plat_probe has already set drvdata so
 * amdxdna_plat_find_by_rproc() succeeds first try.
 *
 * If a channel is somehow announced before any plat_probe completed,
 * drv_probe() returns -EPROBE_DEFER and resets rpdev->src back to
 * RPMSG_ADDR_ANY (the kernel rpmsg core mutates rpdev->src to a
 * concrete address before calling drv_probe and never resets it on
 * probe failure; without our reset, a sibling channel could grab our
 * freed idr slot and break the deferred-probe retry).  drv_remove()
 * does the same reset for symmetry, so rmmod+insmod cycles work too.
 *
 * Discovery (no globals)
 * ----------------------
 * drv_probe() walks up from the rpdev to its owning remoteproc via
 * rproc_get_by_child(), then asks amdxdna_plat.c for the xdna whose
 * ``amd,remoteproc`` phandle resolves there (amdxdna_plat_find_by_rproc()).
 *
 * Channel hot-path
 * ----------------
 * The rpmsg_device pointer is RCU-protected: senders rcu_dereference()
 * on every call so the send path is lock-free; channel-up/-down events
 * use synchronize_rcu() to fence senders out before mutating state.
 */

#include <drm/drm_managed.h>
#include <linux/bitfield.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/rcupdate.h>
#include <linux/remoteproc.h>
#include <linux/rpmsg.h>
#include <linux/slab.h>
#include <linux/xarray.h>

#include "aie4_pci.h"
#include "amdxdna_plat.h"
#include "amdxdna_rpmsg.h"

/*
 * mailbox_verbose: when set, every outgoing RPMsg request is logged with
 * its header sizes and the on-wire frame is hex-dumped at KERN_INFO so
 * it shows up regardless of the dynamic-debug state of this file.  Off
 * by default so production traffic stays quiet.  Toggle at runtime via:
 *   echo 1 > /sys/module/amdxdna/parameters/mailbox_verbose
 */
static int mailbox_verbose;
module_param(mailbox_verbose, int, 0644);
MODULE_PARM_DESC(mailbox_verbose,
		 " Dump RPMsg request header+payload on every send (0=off, 1=on)");

/*
 * Wire header — must match firmware's npu_mbox_msg_header exactly:
 *
 *   offset 0:  total_msg_size
 *   offset 4:  msg_size[10:0] | rsvd[15:11] | protocol_version[23:16] | seq[31:24]
 *   offset 8:  msg_id           ← correlation ID (echoed by firmware)
 *   offset 12: msg_opcode
 */
#define RPMSG_MSG_BODY_SZ	GENMASK(10, 0)
#define RPMSG_MSG_PROTO_VER	GENMASK(23, 16)
#define RPMSG_PROTOCOL_VERSION	0x1

/*
 * RPU platform opcodes (0x40000..0x4FFFF range).
 *
 * Unlike PCI aie4 (which uses a BAR doorbell write to kick CERT), the rpmsg
 * transport carries the doorbell as a regular RPMsg.  The RPU firmware
 * dispatches it through the NPU mgmt switch like any other request and
 * sends back a small ack.  The wire form must match
 * rpu-fw/app/include/aie_mgmt/npu_msg_handler.h:
 *
 *   NPU_MSG_OP_EXEC_HW_CONTEXT (0x40001) — driver→RPU software doorbell.
 *     Payload: __le32 hw_context_id.  RPU replies with a 4-byte status.
 *
 *   NPU_MSG_OP_CMD_COMPLETION  (0x40002) — unsolicited RPU→driver async
 *     notification fired when a command finishes on an HW context.
 *     Payload: struct { __le32 partition_id; __le32 context_id; }.
 *     With polling disabled (no MSI-X is wired over RPMsg), this is the
 *     only wake source for cmd_wait()->check_cmd_done() to re-check the
 *     UMQ host_queue read_index.
 *
 * Kept scoped to this file because these are not part of the upstream
 * aie4 firmware protocol (PCI parts have no equivalent), so they do not
 * belong in aie4_msg_priv.h.  Opcode 0x30010 (the historical value of
 * the doorbell) collides with AIE4_MSG_OP_AIE_COREDUMP on the wire and
 * must not be reused for this purpose.
 */
#define AMDXDNA_RPMSG_OP_EXEC_HW_CONTEXT	0x40001
#define AMDXDNA_RPMSG_OP_CMD_COMPLETION		0x40002

struct amdxdna_rpmsg_doorbell_req {
	__le32 hw_context_id;
} __packed;

struct amdxdna_rpmsg_doorbell_resp {
	__le32 status;
} __packed;

/* Mirrors rpu-fw npu_msg_handler.h:struct npu_msg_cmd_completion. */
struct amdxdna_rpmsg_cmd_completion {
	__le32 partition_id;
	__le32 context_id;
} __packed;

struct rpmsg_msg_header {
	__le32 total_size;
	__le32 sz_ver;
	__le32 id;
	__le32 opcode;
} __packed;

struct rpmsg_inflight_msg {
	u32			id;
	void			*handle;
	int			(*notify_cb)(void *handle, void __iomem *data,
					     size_t size);
};

struct amdxdna_rpmsg_hdl {
	struct amdxdna_dev_hdl	*ndev;
	struct rpmsg_device __rcu *rpdev;
	struct xarray		msg_xa;
	struct mutex		msg_lock;
	u32			next_msg_id;
};

static struct amdxdna_rpmsg_hdl *to_rpmsg_hdl(struct amdxdna_dev_hdl *ndev)
{
	return ndev->xcomm_hdl;
}

/*
 * Handle an unsolicited NPU_MSG_OP_CMD_COMPLETION async notification.
 *
 * The RPU sends this when a command on an HW context has finished and the
 * UMQ host_queue read_index has been advanced.  With polling disabled the
 * driver has no MSI-X over RPMsg, so this message is the sole wake source
 * for any sleeper in aie4_cmd_wait() / wait_till_seq_completed().  The
 * waiter's predicate (check_cmd_done) re-reads read_index from the UMQ
 * shared memory and confirms its own seq, so a broadcast wake is safe:
 * a false wake just re-runs the predicate and goes back to sleep.
 *
 * Mirrors amdxdna_shmem_doorbell_notify() in amdxdna_shmem.c for the
 * shared-memory + IPI transport.
 */
static void
amdxdna_rpmsg_cmd_completion(struct amdxdna_dev_hdl *ndev,
			     const void *payload, size_t payload_len)
{
	const struct amdxdna_rpmsg_cmd_completion *cc = payload;
	struct amdxdna_dev *xdna = ndev->xdna;
	struct cert_comp *cert_comp;
	unsigned long idx;

	if (payload_len < sizeof(*cc)) {
		XDNA_WARN(xdna,
			  "CMD_COMPLETION payload too small (%zu < %zu)",
			  payload_len, sizeof(*cc));
		return;
	}

	XDNA_DBG(xdna, "CMD_COMPLETION partition=%u context=%u",
		 le32_to_cpu(cc->partition_id),
		 le32_to_cpu(cc->context_id));

	xa_lock(&ndev->cert_comp_xa);
	xa_for_each(&ndev->cert_comp_xa, idx, cert_comp)
		wake_up_all(&cert_comp->waitq);
	xa_unlock(&ndev->cert_comp_xa);
}

static int amdxdna_rpmsg_rx_cb(struct rpmsg_device *rpdev, void *data,
			       int len, void *priv, u32 src)
{
	struct amdxdna_dev *xdna = dev_get_drvdata(&rpdev->dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_rpmsg_hdl *rhdl = to_rpmsg_hdl(ndev);
	struct rpmsg_msg_header *hdr = data;
	struct rpmsg_inflight_msg *ifm;
	void *payload;
	size_t payload_len;
	u32 opcode;
	u32 id;

	if (len < sizeof(*hdr)) {
		XDNA_WARN(xdna, "short RPMsg message (%d bytes)", len);
		return -EINVAL;
	}

	id = le32_to_cpu(hdr->id);
	opcode = le32_to_cpu(hdr->opcode);
	payload = hdr + 1;
	payload_len = len - sizeof(*hdr);

	/*
	 * Unsolicited messages carry an opcode we route on directly; they
	 * have no entry in msg_xa because the driver never registered an
	 * inflight request for them.  Dispatch before the id lookup so the
	 * RPU's own msg_id sequence is not confused with our driver-side
	 * sequence.
	 */
	if (opcode == AMDXDNA_RPMSG_OP_CMD_COMPLETION) {
		amdxdna_rpmsg_cmd_completion(ndev, payload, payload_len);
		return 0;
	}

	mutex_lock(&rhdl->msg_lock);
	ifm = xa_erase(&rhdl->msg_xa, id);
	mutex_unlock(&rhdl->msg_lock);

	if (!ifm) {
		XDNA_WARN(xdna, "unexpected RPMsg id %u", id);
		return -ENOENT;
	}

	/*
	 * notify_cb expects void __iomem *, but RPMsg RX data is normal
	 * kernel memory.  The callback only uses memcpy_fromio / readl
	 * which work fine on normal memory, so the cast is safe.
	 */
	if (ifm->notify_cb)
		ifm->notify_cb(ifm->handle, (void __iomem *)payload,
			       payload_len);

	kfree(ifm);
	return 0;
}

static int amdxdna_rpmsg_send_msg(void *xcomm_hdl,
				  const struct xdna_mailbox_msg *msg)
{
	struct amdxdna_rpmsg_hdl *rhdl = xcomm_hdl;
	struct amdxdna_dev *xdna = rhdl->ndev->xdna;
	struct rpmsg_device *rpdev;
	struct rpmsg_inflight_msg *ifm;
	struct rpmsg_msg_header *hdr;
	size_t total;
	u8 *buf;
	u32 id;
	int ret;

	ifm = kzalloc(sizeof(*ifm), GFP_KERNEL);
	if (!ifm)
		return -ENOMEM;

	mutex_lock(&rhdl->msg_lock);
	id = rhdl->next_msg_id++;
	ifm->id = id;
	ifm->handle = msg->handle;
	ifm->notify_cb = msg->notify_cb;

	ret = xa_insert(&rhdl->msg_xa, id, ifm, GFP_KERNEL);
	if (ret) {
		mutex_unlock(&rhdl->msg_lock);
		kfree(ifm);
		return ret;
	}
	mutex_unlock(&rhdl->msg_lock);

	total = sizeof(*hdr) + msg->send_size;
	buf = kzalloc(total, GFP_KERNEL);
	if (!buf) {
		mutex_lock(&rhdl->msg_lock);
		xa_erase(&rhdl->msg_xa, id);
		mutex_unlock(&rhdl->msg_lock);
		kfree(ifm);
		return -ENOMEM;
	}

	hdr = (struct rpmsg_msg_header *)buf;
	hdr->total_size = cpu_to_le32(total);
	hdr->sz_ver = cpu_to_le32(
		FIELD_PREP(RPMSG_MSG_BODY_SZ, msg->send_size) |
		FIELD_PREP(RPMSG_MSG_PROTO_VER, RPMSG_PROTOCOL_VERSION));
	hdr->id = cpu_to_le32(id);
	hdr->opcode = cpu_to_le32(msg->opcode);
	memcpy(buf + sizeof(*hdr), msg->send_data, msg->send_size);

	rcu_read_lock();
	rpdev = rcu_dereference(rhdl->rpdev);
	if (!rpdev) {
		rcu_read_unlock();
		kfree(buf);
		mutex_lock(&rhdl->msg_lock);
		xa_erase(&rhdl->msg_xa, id);
		mutex_unlock(&rhdl->msg_lock);
		kfree(ifm);
		return -ENODEV;
	}
	XDNA_DBG(xdna, "Sending RPMsg message, id: %u, opcode: 0x%x", id, msg->opcode);
	if (mailbox_verbose) {
		/*
		 * Dump the full on-wire frame: 16-byte rpmsg_msg_header
		 * followed by msg->send_size bytes of opcode-specific
		 * payload.  KERN_DEBUG so the dump joins the rest of the
		 * driver's debug output; mailbox_verbose is the runtime
		 * gate.
		 */
		print_hex_dump(KERN_DEBUG, "rpmsg req hdr: ",
			       DUMP_PREFIX_OFFSET, 16, 4,
			       buf, sizeof(*hdr), false);
		if (msg->send_size)
			print_hex_dump(KERN_DEBUG, "rpmsg req payload: ",
				       DUMP_PREFIX_OFFSET, 16, 4,
				       buf + sizeof(*hdr), msg->send_size,
				       false);
	}
	ret = rpmsg_send(rpdev->ept, buf, total);
	rcu_read_unlock();

	kfree(buf);

	if (ret) {
		mutex_lock(&rhdl->msg_lock);
		xa_erase(&rhdl->msg_xa, id);
		mutex_unlock(&rhdl->msg_lock);
		kfree(ifm);
		XDNA_ERR(xdna, "Failed to send RPMsg message, id: %u, opcode: %u, ret: %d", id, msg->opcode, ret);
	}

	return ret;
}

/*
 * Send the data-plane "doorbell" to the RPU firmware.
 *
 * The RPU FW (handle_exec_hw_context) does the actual ring read and AIE
 * dispatch.  We piggy-back on amdxdna_rpmsg_send_msg() so the msg_id
 * bookkeeping works (the FW always replies with a 4-byte status); a NULL
 * notify_cb means amdxdna_rpmsg_rx_cb() will erase the xa entry and drop
 * the response without invoking any callback.
 *
 * Returns 0 on successful enqueue.  Note: this only acknowledges that the
 * RPMsg was handed to the rpmsg core -- the actual command completion is
 * tracked separately via the UMQ host_queue_header.read_index advancing
 * (see ve2_cmd_wait / aie4 wait paths).
 */
static int amdxdna_rpmsg_ring_doorbell(void *xcomm_hdl, u32 hw_ctx_id)
{
	struct amdxdna_rpmsg_doorbell_req req = {
		.hw_context_id = cpu_to_le32(hw_ctx_id),
	};
	struct xdna_mailbox_msg msg = {
		.opcode    = AMDXDNA_RPMSG_OP_EXEC_HW_CONTEXT,
		.handle    = NULL,
		.notify_cb = NULL,
		.send_data = (u8 *)&req,
		.send_size = sizeof(req),
	};

	return amdxdna_rpmsg_send_msg(xcomm_hdl, &msg);
}

/*
 * Final per-device cleanup.  By the time we get here, amdxdna_rpmsg_fini()
 * has detached us from any live rpmsg endpoint via device_release_driver(),
 * which fired drv_remove() and therefore:
 *   - cleared rhdl->rpdev under RCU and synchronize_rcu()-ed,
 *   - drained msg_xa via amdxdna_rpmsg_abort_inflight().
 *
 * If no rpdev was ever connected, msg_xa is empty by construction.  Either
 * way there's nothing left to do but free bookkeeping.
 */
static void amdxdna_rpmsg_xcomm_fini(void *xcomm_hdl)
{
	struct amdxdna_rpmsg_hdl *rhdl = xcomm_hdl;

	WARN_ON(!xa_empty(&rhdl->msg_xa));
	xa_destroy(&rhdl->msg_xa);
	mutex_destroy(&rhdl->msg_lock);
}

static const struct amdxdna_xcomm_ops amdxdna_rpmsg_xcomm_ops = {
	.send_msg	= amdxdna_rpmsg_send_msg,
	.ring_doorbell	= amdxdna_rpmsg_ring_doorbell,
	.fini		= amdxdna_rpmsg_xcomm_fini,
};

/*
 * Internal RPMsg endpoint driver.
 *
 * Bind side: catches the "rpmsg-aie-mgmt" channel announcement from the
 * remoteproc firmware.  Resolves the matching amdxdna platform device by
 * walking up to the owning rproc and asking amdxdna_plat.c for the
 * &amdxdna_dev whose ``amd,remoteproc`` phandle resolves there.  If no
 * platform device has been probed yet (drvdata not set), the bind is
 * deferred — the rpmsg core's deferred-probe machinery will retry once
 * the platform driver finishes binding.  Before deferring we restore
 * rpdev->src to RPMSG_ADDR_ANY because the rpmsg core mutated it to
 * a concrete address before calling us and never resets it on probe
 * failure (a stale value would collide with a sibling channel's idr
 * slot on the retry; same kernel bug also handled in drv_remove).
 *
 * On a successful bind, the channel is now usable and management
 * messages can flow.  We then call amdxdna_plat_register_device() to
 * run the firmware-dependent setup (ops->init, sysfs, drm_dev_register,
 * runtime PM); from this point on userspace can open /dev/accel/accelN.
 */
static int amdxdna_rpmsg_drv_probe(struct rpmsg_device *rpdev)
{
	struct amdxdna_rpmsg_hdl *rhdl;
	struct amdxdna_dev *xdna;
	struct rproc *rproc;
	int ret;

	rproc = rproc_get_by_child(&rpdev->dev);
	if (!rproc) {
		dev_dbg(&rpdev->dev, "RPMsg has no owning remoteproc\n");
		return -ENODEV;
	}

	xdna = amdxdna_plat_find_by_rproc(rproc);
	rproc_put(rproc);
	if (!xdna) {
		dev_dbg(&rpdev->dev, "platform device not probed yet, deferring\n");
		rpdev->src = RPMSG_ADDR_ANY;
		return -EPROBE_DEFER;
	}

	rhdl = to_rpmsg_hdl(xdna->dev_handle);

	/*
	 * Start fresh on every (re)connect so the message-id space is
	 * per-connection.  drv_remove drained any leftover msg_xa entries
	 * before this probe ran, and rhdl->rpdev was NULL until just below,
	 * so no concurrent sender can be observing next_msg_id here.
	 */
	rhdl->next_msg_id = 0;

	rcu_assign_pointer(rhdl->rpdev, rpdev);
	dev_set_drvdata(&rpdev->dev, xdna);

	XDNA_INFO(xdna, "RPMsg channel %s connected", rpdev->id.name);

	/*
	 * Channel is hot — finish device bring-up: ops->init() (firmware
	 * version / metadata queries), sysfs, drm_dev_register, runtime PM.
	 * On failure, undo the channel wire-up so a retry has a clean slate.
	 */
	ret = amdxdna_plat_register_device(xdna);
	if (ret) {
		XDNA_ERR(xdna, "Late device register failed: %d", ret);
		rcu_assign_pointer(rhdl->rpdev, NULL);
		synchronize_rcu();
		dev_set_drvdata(&rpdev->dev, NULL);
		rpdev->src = RPMSG_ADDR_ANY;
		return ret;
	}

	return 0;
}

/*
 * Walk msg_xa and abort every in-flight message by invoking its notify_cb
 * with (handle, NULL, 0).  This mirrors the abort convention used by the
 * legacy mailbox layer (see mailbox_release_msg() in amdxdna_mailbox.c)
 * and is recognized by xdna_msg_cb / aie4_xdna_msg_cb, which both treat
 * !data as "complete the waiter without copying a payload".  Without this
 * drain, channel-down events leave waiters blocked on their completion
 * forever.
 *
 * Caller must guarantee that no new sender can populate msg_xa for the
 * lifetime of the drain — drv_remove satisfies this because it has just
 * cleared rhdl->rpdev under RCU and synchronize_rcu()-ed all senders out
 * of the read-side critical section.
 */
static void amdxdna_rpmsg_abort_inflight(struct amdxdna_rpmsg_hdl *rhdl)
{
	struct rpmsg_inflight_msg *ifm;
	unsigned long idx;

	mutex_lock(&rhdl->msg_lock);
	xa_for_each(&rhdl->msg_xa, idx, ifm) {
		xa_erase(&rhdl->msg_xa, idx);
		if (ifm->notify_cb)
			ifm->notify_cb(ifm->handle, NULL, 0);
		kfree(ifm);
	}
	mutex_unlock(&rhdl->msg_lock);
}

static void amdxdna_rpmsg_drv_remove(struct rpmsg_device *rpdev)
{
	struct amdxdna_dev *xdna = dev_get_drvdata(&rpdev->dev);
	struct amdxdna_rpmsg_hdl *rhdl;

	if (!xdna)
		return;

	rhdl = to_rpmsg_hdl(xdna->dev_handle);

	/*
	 * Roll back the firmware-dependent state first, while the channel
	 * is still alive.  amdxdna_plat_unregister_device() will (in order):
	 *   - drm_dev_unplug      (open fds get clean -ENODEV semantics)
	 *   - sysfs_fini
	 *   - rpm_fini + pm_runtime_disable  (no more autosuspend)
	 *   - ops->fini           (firmware tear-down messages may still
	 *                          go through; that's intentional)
	 *   - destroy notifier_wq
	 * No-op if plat_remove already ran the same sequence (idempotent
	 * on xdna->notifier_wq).
	 */
	amdxdna_plat_unregister_device(xdna);

	rcu_assign_pointer(rhdl->rpdev, NULL);
	synchronize_rcu();

	/* Fail any waiters that were left holding the bag. */
	amdxdna_rpmsg_abort_inflight(rhdl);

	/*
	 * Workaround for a kernel rpmsg-core deficiency: rpmsg_dev_probe()
	 * mutates rpdev->src to the concrete address that idr_alloc()
	 * returned for our endpoint, but neither the probe-failure path
	 * nor rpmsg_dev_remove() restores it to RPMSG_ADDR_ANY.  As a
	 * result, after this rpdev is unbound the next rpmsg_dev_probe()
	 * (e.g. from rmmod+insmod amdxdna in this boot, or from any later
	 * registration of a driver matching this channel) will pass our
	 * stale src as a fixed idr_alloc() request.  If a sibling channel
	 * (rpmsg-tty etc.) grabbed that idr slot in the meantime, the
	 * call returns -ENOSPC and the bind permanently fails until the
	 * remoteproc is restarted.  Resetting src here closes that gap.
	 */
	rpdev->src = RPMSG_ADDR_ANY;
	dev_set_drvdata(&rpdev->dev, NULL);

	XDNA_INFO(xdna, "RPMsg channel %s disconnected", rpdev->id.name);
}

static const struct rpmsg_device_id amdxdna_rpmsg_id_table[] = {
	{ .name = "rpmsg-aie-mgmt" },
	{ },
};

static struct rpmsg_driver amdxdna_rpmsg_driver = {
	.drv.name	= "amdxdna_rpmsg",
	.id_table	= amdxdna_rpmsg_id_table,
	.probe		= amdxdna_rpmsg_drv_probe,
	.remove		= amdxdna_rpmsg_drv_remove,
	.callback	= amdxdna_rpmsg_rx_cb,
};

/*
 * Module-level (un)registration of the rpmsg endpoint driver.
 *
 * Called from amdxdna_plat.c's module_init/module_exit.  See
 * amdxdna_rpmsg.h for the ordering contract: the platform_driver must
 * already be registered (and its plat_probe() may have run) before
 * amdxdna_rpmsg_drv_register() runs, so the rpmsg core's synchronous
 * bus walk inside register_rpmsg_driver() can find a probed xdna via
 * amdxdna_plat_find_by_rproc().
 *
 * If a channel is somehow announced before any plat_probe completes,
 * drv_probe() returns -EPROBE_DEFER (with rpdev->src reset back to
 * RPMSG_ADDR_ANY) and the kernel's deferred-probe machinery retries
 * once the plat device is bound.  Resetting src is critical: the
 * rpmsg core mutates rpdev->src to a concrete address before calling
 * drv_probe and never restores it on probe failure, so without the
 * reset a sibling channel could grab our freed idr slot and break
 * the retry permanently.
 */
int amdxdna_rpmsg_drv_register(void)
{
	return register_rpmsg_driver(&amdxdna_rpmsg_driver);
}

void amdxdna_rpmsg_drv_unregister(void)
{
	unregister_rpmsg_driver(&amdxdna_rpmsg_driver);
}

/**
 * amdxdna_rpmsg_init - Set up per-device rpmsg transport state.
 * @xdna: the amdxdna device
 *
 * Allocates the per-device rpmsg handle (rhdl) and installs xcomm_ops/
 * xcomm_hdl on ndev so management code can route messages over the
 * channel.  Does NOT touch the global rpmsg driver registration (that
 * happens once at module_init) and does NOT block on rproc readiness
 * or channel announcement: rhdl->rpdev may still be NULL on return.
 * In that window:
 *
 *   - send_msg / ring_doorbell return -ENODEV (callers retry / wait).
 *   - When the rpmsg core dispatches the channel announcement,
 *     drv_probe() discovers this xdna via amdxdna_plat_find_by_rproc()
 *     and installs rhdl->rpdev under RCU.
 *
 * Return: 0 on success, negative errno otherwise.
 */
int amdxdna_rpmsg_init(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_rpmsg_hdl *rhdl;

	rhdl = drmm_kzalloc(&xdna->ddev, sizeof(*rhdl), GFP_KERNEL);
	if (!rhdl)
		return -ENOMEM;

	rhdl->ndev = ndev;
	RCU_INIT_POINTER(rhdl->rpdev, NULL);
	xa_init(&rhdl->msg_xa);
	mutex_init(&rhdl->msg_lock);

	ndev->xcomm_ops = &amdxdna_rpmsg_xcomm_ops;
	ndev->xcomm_hdl = rhdl;

	return 0;
}

void amdxdna_rpmsg_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_rpmsg_hdl *rhdl = to_rpmsg_hdl(ndev);
	struct rpmsg_device *rpdev;

	/*
	 * Detach this xdna's specific rpdev (if any), so a peer AIE
	 * device's binding is undisturbed.  device_release_driver()
	 * synchronously fires drv_remove(), which:
	 *   - calls amdxdna_plat_unregister_device() (drm_dev_unplug,
	 *     sysfs_fini, ops->fini, rpm_fini, destroy notifier_wq);
	 *   - RCU-clears rhdl->rpdev + drains msg_xa;
	 *   - resets rpdev->src to RPMSG_ADDR_ANY.
	 * Holding a device ref across the call keeps the rpdev struct
	 * alive even if remoteproc subdev teardown races with us.
	 *
	 * If the rpdev is already gone (e.g. `echo stop` on the
	 * remoteproc before unbinding), rhdl->rpdev is NULL — nothing
	 * to detach from.
	 */
	rcu_read_lock();
	rpdev = rcu_dereference(rhdl->rpdev);
	if (rpdev)
		get_device(&rpdev->dev);
	rcu_read_unlock();

	if (rpdev) {
		device_release_driver(&rpdev->dev);
		put_device(&rpdev->dev);
	}

	if (ndev->xcomm_ops && ndev->xcomm_ops->fini)
		ndev->xcomm_ops->fini(ndev->xcomm_hdl);

	ndev->xcomm_ops = NULL;
	ndev->xcomm_hdl = NULL;
}
