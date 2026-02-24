// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include <linux/pci.h>

#include "aie4_pci.h"
#include "aie4_message.h"
#include "aie4_msg_priv.h"

#define NUM_VF 4

static int aie4_sriov_stop(struct amdxdna_dev_hdl *ndev)
{
	DECLARE_AIE4_MSG(aie4_msg_destroy_vfs, AIE4_MSG_OP_DESTROY_VFS);
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);
	int ret;

	if (ndev->num_vfs == 0)
		return 0;

	ret = pci_sriov_configure_simple(pdev, 0);
	if (ret) {
		XDNA_ERR(xdna, "configure vfs to 0 failed: %d", ret);
		return ret;
	}

	ndev->num_vfs = 0;
	req.rsvd = 0;
	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);
	if (ret)
		XDNA_ERR(xdna, "destroy vfs op failed: %d", ret);

	return ret;
}

static int aie4_sriov_start(struct amdxdna_dev_hdl *ndev, int num_vfs)
{
	DECLARE_AIE4_MSG(aie4_msg_create_vfs, AIE4_MSG_OP_CREATE_VFS);
	struct amdxdna_dev *xdna = ndev->xdna;
	struct pci_dev *pdev = to_pci_dev(xdna->ddev.dev);

	int ret;

	if (num_vfs > NUM_VF) {
		XDNA_ERR(xdna, "num_vfs %d greater then supported %d", num_vfs, NUM_VF);
		return -EINVAL;
	}

	ndev->num_vfs = num_vfs;
	req.vf_cnt = ndev->num_vfs;
	mutex_lock(&ndev->aie4_lock);
	ret = aie4_send_msg_wait(ndev, &msg);
	mutex_unlock(&ndev->aie4_lock);
	if (ret) {
		XDNA_ERR(xdna, "create vfs op failed: %d", ret);
		return ret;
	}

	return pci_sriov_configure_simple(pdev, ndev->num_vfs);
}

int aie4_sriov_configure(struct amdxdna_dev *xdna, int num_vfs)
{
	struct amdxdna_dev_hdl *ndev = xdna->dev_handle;

	return (num_vfs == 0) ? aie4_sriov_stop(ndev) : aie4_sriov_start(ndev, num_vfs);
}
