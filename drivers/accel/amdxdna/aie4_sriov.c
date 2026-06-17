// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "drm/amdxdna_accel.h"
#include <drm/drm_drv.h>
#include <drm/drm_print.h>
#include <linux/pci.h>

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
		/*
		 * VFs are assigned to VMs (passthrough).
		 * The pci_disable_sriov cannot be called safely.
		 * thus, return early.
		 */
		XDNA_ERR(xdna, "VFs are still assigned to VMs");
		return -EPERM;
	}

	/*
	 * Notify firmware that VFs are being torn down.
	 * this is requested by privileged PF driver, thus continue
	 * to tear down VF config space. It is up to the admin if any
	 * error reported in this stage. They should either reload the
	 * firmware or even reset the device.
	 */
	ret = aie4_destroy_vfs(ndev);
	ndev->num_vfs = 0;
	pci_disable_sriov(pdev);

	return ret;
}

static void aie4_for_each_vf(struct amdxdna_dev *xdna,
			     void (*fn)(struct pci_dev *pf, struct pci_dev *vf))
{
	struct pci_dev *pdev_pf = to_pci_dev(xdna->ddev.dev);
	struct pci_dev *pdev_vf;
	int pos;
	u16 vf_did;

	pos = pci_find_ext_capability(pdev_pf, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return;

	if (pci_read_config_word(pdev_pf, pos + PCI_SRIOV_VF_DID, &vf_did)) {
		XDNA_WARN(xdna, "Failed to read VF device ID");
		return;
	}

	for (pdev_vf = pci_get_device(pdev_pf->vendor, vf_did, NULL);
	     pdev_vf;
	     pdev_vf = pci_get_device(pdev_pf->vendor, vf_did, pdev_vf)) {
		if (!pdev_vf->is_virtfn || pdev_vf->physfn != pdev_pf)
			continue;
		fn(pdev_pf, pdev_vf);
	}
}

static void aie4_link_one_vf(struct pci_dev *pf, struct pci_dev *vf)
{
	struct amdxdna_dev *xdna = pci_get_drvdata(pf);
	struct device_link *link;

	/*
	 * Link VF (consumer) to PF (supplier) for PM runtime ordering.
	 * DL_FLAG_AUTOREMOVE_SUPPLIER drops the link object when the PF is
	 * removed; it does not itself enforce VF-before-PF teardown ordering.
	 * That ordering is enforced explicitly by aie4_unplug_vfs() and
	 * pci_disable_sriov() in the removal path.
	 */
	link = device_link_add(&vf->dev,   /* consumer = VF */
			       &pf->dev,   /* supplier = PF */
			       DL_FLAG_PM_RUNTIME | DL_FLAG_AUTOREMOVE_SUPPLIER);

	if (!link)
		XDNA_WARN(xdna, "Failed to link VF %s", pci_name(vf));
	else
		XDNA_DBG(xdna, "Linked VF %s", pci_name(vf));
}

static void aie4_unplug_one_vf(struct pci_dev *pf, struct pci_dev *vf)
{
	struct amdxdna_dev *vf_xdna;

	/*
	 * Only unplug VFs bound to the same driver. VFs set to passthrough are
	 * owned by different driver, the vfio-pci driver.
	 */
	if (pf->driver != vf->driver)
		return;

	vf_xdna = pci_get_drvdata(vf);
	if (!vf_xdna)
		return;

	drm_dev_unplug(&vf_xdna->ddev);
}

static void aie4_link_vfs(struct amdxdna_dev *xdna)
{
	XDNA_DBG(xdna, "Linking VFs to PF %s", pci_name(to_pci_dev(xdna->ddev.dev)));
	aie4_for_each_vf(xdna, aie4_link_one_vf);
}

void aie4_unplug_vfs(struct amdxdna_dev_hdl *ndev)
{
	struct amdxdna_dev *xdna = ndev->aie.xdna;

	XDNA_DBG(xdna, "Unplugging VFs from PF %s", pci_name(to_pci_dev(xdna->ddev.dev)));
	aie4_for_each_vf(xdna, aie4_unplug_one_vf);
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

	if (num_vfs)
		return aie4_sriov_start(ndev, num_vfs);

	/* Block new traffic from amdxdna-managed VFs */
	aie4_unplug_vfs(ndev);
	return aie4_sriov_stop(ndev);
}
