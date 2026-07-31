// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_print.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>

#include "aie.h"
#include "aie4_msg_priv.h"
#include "aie4_pci.h"
#include "amdxdna_mailbox.h"
#include "amdxdna_mailbox_helper.h"
#include "amdxdna_pci_drv.h"

static int aie4_destroy_vfs(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE_MSG(aie4_msg_destroy_vfs, AIE4_MSG_OP_DESTROY_VFS);
	int ret;

	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(ndev->aie.xdna, "destroy vfs op failed: %d", ret);

	return ret;
}

int aie4_create_vfs(struct amdxdna_dev_hdl *ndev, int num_vfs)
{
	DECLARE_AIE_MSG(aie4_msg_create_vfs, AIE4_MSG_OP_CREATE_VFS);
	int ret;

	req.vf_cnt = num_vfs;
	ret = aie_send_mgmt_msg_wait(&ndev->aie, &msg);
	if (ret)
		XDNA_ERR(ndev->aie.xdna, "create vfs op failed: %d", ret);

	return ret;
}

int aie4_sriov_stop(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	if (!pci_num_vf(pdev))
		return 0;

	ret = pci_vfs_assigned(pdev);
	if (ret) {
		XDNA_ERR(xdna, "VFs are still assigned to VMs");
		return -EPERM;
	}

	pci_disable_sriov(pdev);
	ndev->num_vfs = 0;

	/*
	 * pci_disable_sriov() removes VF drivers first; call destroy_vfs after
	 * so firmware VF contexts are not cleared before VF drivers finish cleanup.
	 */
	return aie4_destroy_vfs(ndev);
}

static int aie4_for_each_vfs(struct amdxdna_dev *xdna,
			     int (*cb)(struct amdxdna_dev *, struct pci_dev *))
{
	struct pci_dev *pdev_pf = to_pci_dev(xdna->ddev.dev);
	struct pci_dev *pdev_vf;
	int pos, ret;
	u16 vf_did;

	pos = pci_find_ext_capability(pdev_pf, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return 0;
	ret = pci_read_config_word(pdev_pf, pos + PCI_SRIOV_VF_DID, &vf_did);
	if (ret) {
		XDNA_ERR(xdna, "read VF Device ID failed %d", ret);
		return -ENODEV;
	}

	for (pdev_vf = pci_get_device(pdev_pf->vendor, vf_did, NULL);
	     pdev_vf;
	     pdev_vf = pci_get_device(pdev_pf->vendor, vf_did, pdev_vf)) {
		if (!pdev_vf->is_virtfn || pdev_vf->physfn != pdev_pf)
			continue;

		ret = cb(xdna, pdev_vf);
		if (ret) {
			/*
			 * On early return the next iteration never runs, so
			 * release the current device's ref manually.
			 * On normal loop exit pci_get_device() returning NULL
			 * already releases the last device's ref internally.
			 */
			pci_dev_put(pdev_vf);
			return ret;
		}
	}

	return 0;
}

static int aie4_link_vf(struct amdxdna_dev *xdna, struct pci_dev *pdev_vf)
{
	struct pci_dev *pdev_pf = to_pci_dev(xdna->ddev.dev);
	struct device_link *link;

	link = device_link_add(&pdev_vf->dev,   /* consumer = VF */
			       &pdev_pf->dev,   /* supplier = PF */
			       DL_FLAG_PM_RUNTIME | DL_FLAG_AUTOREMOVE_CONSUMER);
	if (!link)
		XDNA_WARN(xdna, "Failed to link VF %s", pci_name(pdev_vf));
	else
		XDNA_DBG(xdna, "Linked VF %s", pci_name(pdev_vf));
	return 0;
}

static int aie4_check_vf_alive(struct amdxdna_dev *xdna, struct pci_dev *pdev_vf)
{
	struct device_driver *drv = READ_ONCE(pdev_vf->dev.driver);

	if (drv && drv->owner != THIS_MODULE) {
		XDNA_WARN(xdna, "VF:%s is in passthrough", pci_name(pdev_vf));
		return -EBUSY;
	}

	if (!pm_runtime_suspended(&pdev_vf->dev)) {
		XDNA_WARN(xdna, "VF:%s is busy", pci_name(pdev_vf));
		return -EBUSY;
	}
	return 0;
}

int aie4_vfs_alive(struct amdxdna_dev *xdna)
{
	if (pci_vfs_assigned(to_pci_dev(xdna->ddev.dev))) {
		XDNA_WARN(xdna, "VF devices are being used in VMs, cannot suspend");
		return -EBUSY;
	}
	return aie4_for_each_vfs(xdna, aie4_check_vf_alive);
}

static void aie4_link_vfs(struct amdxdna_dev *xdna)
{
	aie4_for_each_vfs(xdna, aie4_link_vf);
}

static int aie4_sriov_start(struct amdxdna_dev_hdl *ndev, int num_vfs)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	ret = aie4_create_vfs(ndev, num_vfs);
	if (ret)
		return ret;

	ret = pci_enable_sriov(pdev, num_vfs);
	if (ret) {
		XDNA_ERR(xdna, "configure VFs failed, ret: %d", ret);
		aie4_destroy_vfs(ndev);
		return ret;
	}

	aie4_link_vfs(xdna);

	ndev->num_vfs = num_vfs;
	return num_vfs;
}

int aie4_sriov_configure(struct amdxdna_dev *xdna, int num_vfs)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	drm_WARN_ON(&xdna->ddev, !mutex_is_locked(&xdna->dev_lock));

	return (num_vfs) ? aie4_sriov_start(ndev, num_vfs) : aie4_sriov_stop(ndev);
}
