// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * RPMsg transport layer for amdxdna.
 *
 * Provides the xcomm_ops implementation that sends management messages and
 * doorbell notifications over an RPMsg channel.  The platform driver
 * (amdxdna_plat.c) calls amdxdna_rpmsg_init() to set up the transport and
 * register an internal RPMsg endpoint driver.  The RPMsg endpoint connects
 * asynchronously when the remoteproc boots and firmware announces the
 * "rpmsg-aie-mgmt" service.
 *
 * The rpmsg_device pointer is RCU-protected so the hot send path is
 * lock-free while the rare channel-up/down events use synchronize_rcu().
 */

#include <drm/drm_managed.h>
#include <linux/bitfield.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/rcupdate.h>
#include <linux/remoteproc.h>
#include <linux/rpmsg.h>
#include <linux/slab.h>
#include <linux/xarray.h>

#include "aie4_pci.h"
#include "amdxdna_rpmsg.h"

/*
 * Module-scoped xdna device pointer.  Set by amdxdna_rpmsg_init() and
 * read by the internal RPMsg driver probe to wire the channel into the
 * platform device.  Only one AIE platform device is supported per module
 * instance.
 */
static struct amdxdna_dev *rpmsg_xdna_dev;

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
	struct rproc		*rproc;
	struct xarray		msg_xa;
	struct mutex		msg_lock;
	u32			next_msg_id;
};

static struct amdxdna_rpmsg_hdl *to_rpmsg_hdl(struct amdxdna_dev_hdl *ndev)
{
	return ndev->xcomm_hdl;
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
	u32 id;

	if (len < sizeof(*hdr)) {
		XDNA_WARN(xdna, "short RPMsg message (%d bytes)", len);
		return -EINVAL;
	}

	id = le32_to_cpu(hdr->id);
	payload = hdr + 1;
	payload_len = len - sizeof(*hdr);

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
	ret = rpmsg_send(rpdev->ept, buf, total);
	rcu_read_unlock();

	kfree(buf);

	if (ret) {
		mutex_lock(&rhdl->msg_lock);
		xa_erase(&rhdl->msg_xa, id);
		mutex_unlock(&rhdl->msg_lock);
		kfree(ifm);
	}

	return ret;
}

static int amdxdna_rpmsg_ring_doorbell(void *xcomm_hdl, u32 hw_ctx_id)
{
	struct amdxdna_rpmsg_hdl *rhdl = xcomm_hdl;
	struct rpmsg_device *rpdev;
	/* TODO: define a proper doorbell opcode in the firmware */
	struct rpmsg_msg_header hdr = {
		.total_size = cpu_to_le32(sizeof(hdr)),
		.sz_ver = cpu_to_le32(
			FIELD_PREP(RPMSG_MSG_PROTO_VER, RPMSG_PROTOCOL_VERSION)),
		.id = cpu_to_le32(hw_ctx_id),
		.opcode = 0,
	};
	int ret;

	rcu_read_lock();
	rpdev = rcu_dereference(rhdl->rpdev);
	if (!rpdev) {
		rcu_read_unlock();
		return -ENODEV;
	}
	ret = rpmsg_send(rpdev->ept, &hdr, sizeof(hdr));
	rcu_read_unlock();

	return ret;
}

static void amdxdna_rpmsg_xcomm_fini(void *xcomm_hdl)
{
	struct amdxdna_rpmsg_hdl *rhdl = xcomm_hdl;
	struct rpmsg_inflight_msg *ifm;
	unsigned long idx;

	rcu_assign_pointer(rhdl->rpdev, NULL);
	synchronize_rcu();

	xa_for_each(&rhdl->msg_xa, idx, ifm)
		kfree(ifm);
	xa_destroy(&rhdl->msg_xa);
	mutex_destroy(&rhdl->msg_lock);
}

static const struct amdxdna_xcomm_ops amdxdna_rpmsg_xcomm_ops = {
	.send_msg	= amdxdna_rpmsg_send_msg,
	.ring_doorbell	= amdxdna_rpmsg_ring_doorbell,
	.fini		= amdxdna_rpmsg_xcomm_fini,
};

/*
 * Internal RPMsg endpoint driver.  Registered by amdxdna_rpmsg_init() to
 * catch the "rpmsg-aie-mgmt" service announcement from the remoteproc
 * firmware.  Probe wires the RPMsg endpoint into the platform device's
 * transport layer; remove nullifies the pointer so in-flight senders
 * get -ENODEV.
 */
static int amdxdna_rpmsg_drv_probe(struct rpmsg_device *rpdev)
{
	struct amdxdna_dev *xdna = rpmsg_xdna_dev;
	struct amdxdna_rpmsg_hdl *rhdl;
	struct rproc *rproc;

	if (!xdna) {
		dev_err(&rpdev->dev, "no xdna platform device\n");
		return -ENODEV;
	}

	rhdl = to_rpmsg_hdl(xdna->dev_handle);

	/* Verify this channel belongs to the expected remoteproc */
	if (rhdl->rproc) {
		rproc = rproc_get_by_child(&rpdev->dev);
		if (rproc != rhdl->rproc) {
			dev_dbg(&rpdev->dev,
				"RPMsg from unexpected rproc, ignoring\n");
			return -ENODEV;
		}
	}

	rcu_assign_pointer(rhdl->rpdev, rpdev);
	dev_set_drvdata(&rpdev->dev, xdna);

	XDNA_INFO(xdna, "RPMsg channel %s connected", rpdev->id.name);
	return 0;
}

static void amdxdna_rpmsg_drv_remove(struct rpmsg_device *rpdev)
{
	struct amdxdna_dev *xdna = dev_get_drvdata(&rpdev->dev);
	struct amdxdna_rpmsg_hdl *rhdl;

	if (!xdna)
		return;

	rhdl = to_rpmsg_hdl(xdna->dev_handle);
	rcu_assign_pointer(rhdl->rpdev, NULL);
	synchronize_rcu();

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

/**
 * amdxdna_rpmsg_init - Set up RPMsg transport for an amdxdna device
 * @xdna: the amdxdna device
 * @np: device tree node with required "amd,remoteproc" phandle
 *
 * Resolves the remoteproc from the "amd,remoteproc" phandle, registers
 * the internal RPMsg driver, and verifies the "rpmsg-aie-mgmt" channel
 * is connected.  Returns -EPROBE_DEFER if either the remoteproc is not
 * registered or the RPMsg channel has not been announced yet.
 *
 * When register_rpmsg_driver() is called, the driver core tries to
 * match against already-existing RPMsg devices.  If the remoteproc is
 * running and firmware has announced "rpmsg-aie-mgmt", the internal
 * RPMsg probe fires synchronously and sets rhdl->rpdev.
 *
 * Return: 0 on success, -EPROBE_DEFER if not ready, negative errno
 */
int amdxdna_rpmsg_init(struct amdxdna_dev *xdna, struct device_node *np)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_rpmsg_hdl *rhdl;
	struct rproc *rproc;
	phandle ph;
	int ret;

	ret = of_property_read_u32(np, "amd,remoteproc", &ph);
	if (ret) {
		XDNA_ERR(xdna, "Missing amd,remoteproc phandle: %d", ret);
		return ret;
	}

	rproc = rproc_get_by_phandle(ph);
	if (!rproc) {
		XDNA_DBG(xdna, "Remoteproc not ready, deferring");
		return -EPROBE_DEFER;
	}
	XDNA_INFO(xdna, "Bound to remoteproc %s", rproc->name);

	rhdl = drmm_kzalloc(&xdna->ddev, sizeof(*rhdl), GFP_KERNEL);
	if (!rhdl) {
		rproc_put(rproc);
		return -ENOMEM;
	}

	rhdl->ndev = ndev;
	rhdl->rproc = rproc;
	RCU_INIT_POINTER(rhdl->rpdev, NULL);
	xa_init(&rhdl->msg_xa);
	mutex_init(&rhdl->msg_lock);

	ndev->xcomm_ops = &amdxdna_rpmsg_xcomm_ops;
	ndev->xcomm_hdl = rhdl;

	rpmsg_xdna_dev = xdna;

	/*
	 * If the remoteproc is running and firmware has already announced
	 * "rpmsg-aie-mgmt", amdxdna_rpmsg_drv_probe() fires synchronously
	 * inside register_rpmsg_driver() and sets rhdl->rpdev.
	 */
	ret = register_rpmsg_driver(&amdxdna_rpmsg_driver);
	if (ret) {
		XDNA_ERR(xdna, "Failed to register RPMsg driver: %d", ret);
		goto fail;
	}

	if (!rcu_access_pointer(rhdl->rpdev)) {
		XDNA_DBG(xdna, "RPMsg channel not available, deferring");
		unregister_rpmsg_driver(&amdxdna_rpmsg_driver);
		ret = -EPROBE_DEFER;
		goto fail;
	}

	return 0;

fail:
	rpmsg_xdna_dev = NULL;
	rproc_put(rproc);
	return ret;
}

void amdxdna_rpmsg_fini(struct amdxdna_dev *xdna)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;
	struct amdxdna_rpmsg_hdl *rhdl = to_rpmsg_hdl(ndev);

	unregister_rpmsg_driver(&amdxdna_rpmsg_driver);

	if (ndev->xcomm_ops && ndev->xcomm_ops->fini)
		ndev->xcomm_ops->fini(ndev->xcomm_hdl);

	if (rhdl->rproc)
		rproc_put(rhdl->rproc);

	ndev->xcomm_ops = NULL;
	ndev->xcomm_hdl = NULL;
	rpmsg_xdna_dev = NULL;
}
