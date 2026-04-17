// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 *
 * RPMsg-based transport driver for amdxdna.
 *
 * When CONFIG_AMDXDNA_RPMSG is enabled, this file is the main driver entry
 * point.  The module registers a single RPMsg endpoint driver bound to the
 * "rpmsg-aie-mgmt" service name.  When the remote processor announces that
 * service, probe creates a DRM/accel device and wires the management message
 * path through the RPMsg channel.  No PCI BARs, MMIO, PSP, SMU, or IRQ
 * vectors are needed -- the remote side owns the hardware.
 */

#include <drm/drm_accel.h>
#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rpmsg.h>
#include <linux/slab.h>
#include <linux/xarray.h>

#include "drm_local/amdxdna_accel.h"
#include "aie4_pci.h"
#include "amdxdna_pci_drv.h"
#include "npu3_family.h"
#include "aie4_message.h"
#include "amdxdna_pm.h"
#include "amdxdna_sysfs.h"

enum rpmsg_msg_type {
	RPMSG_MSG_MGMT = 0,
	RPMSG_MSG_DOORBELL = 1,
};

struct rpmsg_msg_header {
	__le32 total_size;
	__le32 id;
	__le32 opcode;
	__le32 type;
} __packed;

struct rpmsg_inflight_msg {
	u32			id;
	void			*handle;
	int			(*notify_cb)(void *handle, void __iomem *data,
					     size_t size);
};

static void amdxdna_rpmsg_doorbell_notify(struct amdxdna_dev_hdl *ndev, u32 id)
{
	struct cert_comp *cert_comp;
	unsigned long flags;

	xa_lock_irqsave(&ndev->cert_comp_xa, flags);
	cert_comp = xa_load(&ndev->cert_comp_xa, id);
	xa_unlock_irqrestore(&ndev->cert_comp_xa, flags);

	if (cert_comp)
		wake_up_all(&cert_comp->waitq);
	else
		XDNA_WARN(ndev->xdna, "doorbell notify for unknown id %u", id);
}

struct amdxdna_rpmsg_hdl {
	struct amdxdna_dev_hdl	*ndev;
	struct rpmsg_device	*rpdev;
	struct xarray		msg_xa;
	struct mutex		msg_lock; /* serialise send + xa */
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
	u32 id, type;

	if (len < sizeof(*hdr)) {
		XDNA_WARN(xdna, "short RPMsg message (%d bytes)", len);
		return -EINVAL;
	}

	id = le32_to_cpu(hdr->id);
	type = le32_to_cpu(hdr->type);
	payload = hdr + 1;
	payload_len = len - sizeof(*hdr);

	if (type == RPMSG_MSG_DOORBELL) {
		amdxdna_rpmsg_doorbell_notify(ndev, id);
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
	struct rpmsg_inflight_msg *ifm;
	struct rpmsg_msg_header *hdr;
	size_t total;
	u8 *buf;
	u32 id;
	int ret;

	if (!rhdl->rpdev)
		return -ENODEV;

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
	hdr->id = cpu_to_le32(id);
	hdr->opcode = cpu_to_le32(msg->opcode);
	hdr->type = cpu_to_le32(RPMSG_MSG_MGMT);
	memcpy(buf + sizeof(*hdr), msg->send_data, msg->send_size);

	ret = rpmsg_send(rhdl->rpdev->ept, buf, total);
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
	struct rpmsg_msg_header hdr = {
		.total_size = cpu_to_le32(sizeof(hdr)),
		.id = cpu_to_le32(hw_ctx_id),
		.opcode = 0,
		.type = cpu_to_le32(RPMSG_MSG_DOORBELL),
	};

	if (!rhdl->rpdev)
		return -ENODEV;

	return rpmsg_send(rhdl->rpdev->ept, &hdr, sizeof(hdr));
}

static void amdxdna_rpmsg_fini(void *xcomm_hdl)
{
	struct amdxdna_rpmsg_hdl *rhdl = xcomm_hdl;
	struct rpmsg_inflight_msg *ifm;
	unsigned long idx;

	xa_for_each(&rhdl->msg_xa, idx, ifm)
		kfree(ifm);
	xa_destroy(&rhdl->msg_xa);
	mutex_destroy(&rhdl->msg_lock);
}

static const struct amdxdna_xcomm_ops amdxdna_rpmsg_xcomm_ops = {
	.send_msg	= amdxdna_rpmsg_send_msg,
	.ring_doorbell	= amdxdna_rpmsg_ring_doorbell,
	.fini		= amdxdna_rpmsg_fini,
};

static int amdxdna_rpmsg_probe(struct rpmsg_device *rpdev)
{
	struct device *dev = &rpdev->dev;
	const struct amdxdna_dev_info *dev_info;
	struct amdxdna_rpmsg_hdl *rhdl;
	struct amdxdna_dev_hdl *ndev;
	struct amdxdna_dev *xdna;
	int ret;

	dev_info = (const struct amdxdna_dev_info *)rpdev->id.driver_data;
	if (!dev_info) {
		dev_err(dev, "No device info for RPMsg channel %s\n", rpdev->id.name);
		return -ENODEV;
	}

	xdna = devm_drm_dev_alloc(dev, &amdxdna_drm_drv,
				  typeof(*xdna), ddev);
	if (IS_ERR(xdna))
		return PTR_ERR(xdna);

	xdna->dev_info = dev_info;
	xdna->vbnv = dev_info->default_vbnv;

	drmm_mutex_init(&xdna->ddev, &xdna->dev_lock);
	init_rwsem(&xdna->notifier_lock);
	INIT_LIST_HEAD(&xdna->client_list);

	if (IS_ENABLED(CONFIG_LOCKDEP)) {
		fs_reclaim_acquire(GFP_KERNEL);
		might_lock(&xdna->notifier_lock);
		fs_reclaim_release(GFP_KERNEL);
	}

	ndev = drmm_kzalloc(&xdna->ddev, sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		return -ENOMEM;

	rhdl = drmm_kzalloc(&xdna->ddev, sizeof(*rhdl), GFP_KERNEL);
	if (!rhdl)
		return -ENOMEM;

	rhdl->ndev = ndev;
	rhdl->rpdev = rpdev;
	xa_init(&rhdl->msg_xa);
	mutex_init(&rhdl->msg_lock);

	ndev->priv = xdna->dev_info->dev_priv;
	ndev->xdna = xdna;
	ndev->xcomm_ops = &amdxdna_rpmsg_xcomm_ops;
	ndev->xcomm_hdl = rhdl;
	xa_init(&ndev->cert_comp_xa);
	mutex_init(&ndev->aie4_lock);

	xdna->dev_handle = ndev;
	dev_set_drvdata(dev, xdna);

	xdna->notifier_wq = alloc_ordered_workqueue("notifier_wq",
						     WQ_MEM_RECLAIM);
	if (!xdna->notifier_wq)
		return -ENOMEM;

	ret = amdxdna_sysfs_init(xdna);
	if (ret)
		goto destroy_wq;

	ret = drm_dev_register(&xdna->ddev, 0);
	if (ret)
		goto sysfs_fini;

	XDNA_INFO(xdna, "RPMsg driver probed (rpmsg-aie-mgmt)");
	return 0;

sysfs_fini:
	amdxdna_sysfs_fini(xdna);
destroy_wq:
	destroy_workqueue(xdna->notifier_wq);
	return ret;
}

static void amdxdna_rpmsg_remove(struct rpmsg_device *rpdev)
{
	struct amdxdna_dev *xdna = dev_get_drvdata(&rpdev->dev);
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	destroy_workqueue(xdna->notifier_wq);
	drm_dev_unplug(&xdna->ddev);
	amdxdna_sysfs_fini(xdna);

	if (ndev->xcomm_ops && ndev->xcomm_ops->fini)
		ndev->xcomm_ops->fini(ndev->xcomm_hdl);
}

static const struct rpmsg_device_id amdxdna_rpmsg_id_table[] = {
	{ .name = "rpmsg-aie-mgmt",
	  .driver_data = (kernel_ulong_t)&dev_npu3_info },
	{ },
};
MODULE_DEVICE_TABLE(rpmsg, amdxdna_rpmsg_id_table);

static struct rpmsg_driver amdxdna_rpmsg_driver = {
	.drv.name	= AMDXDNA_DRIVER_NAME,
	.id_table	= amdxdna_rpmsg_id_table,
	.probe		= amdxdna_rpmsg_probe,
	.remove		= amdxdna_rpmsg_remove,
	.callback	= amdxdna_rpmsg_rx_cb,
};

static int __init amdxdna_rpmsg_init(void)
{
	printk(KERN_INFO "amdxdna_rpmsg_init\n");
	return register_rpmsg_driver(&amdxdna_rpmsg_driver);
}

static void __exit amdxdna_rpmsg_exit(void)
{
	unregister_rpmsg_driver(&amdxdna_rpmsg_driver);
}

module_init(amdxdna_rpmsg_init);
module_exit(amdxdna_rpmsg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XRT Team <runtimeca39d@amd.com>");
MODULE_DESCRIPTION("amdxdna RPMsg driver");
