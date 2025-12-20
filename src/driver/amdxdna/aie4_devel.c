// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2022-2025 Advanced Micro Devices, Inc.
 * All rights reserved.
 */

#ifdef UMQ_HELLO_TEST
#include <linux/types.h>
#include <linux/delay.h>

#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#include "amdxdna_carvedout_buf.h"

#include "aie4_pci.h"
#include "aie4_message.h"
#include "aie4_devel.h"
#include "aie4_msg_priv.h"

#define KB(x) ((x) << 10)
#define MB(x) (KB(KB(x)))
#define IN_MAGIC 0x55534552 // USER
#define OUT_MAGIC 0x43455254 // CERT

/*
 * Test code for hello memory read/write of HSA queue.
 * Note:
 * 1) this requires hwctx.cpp to alloc 2MB buffer as umq_bo
 * 2) this requires special app_hello.elf pre-loaded in simnow.
 *    how to build app_hello.elf
 *    cd cert/main
 *    make HELLO_HSA_TEST=1 NON_SLEEP=1 LOG_LEVEL=2
 * 3) build driver with -hello_umq
 * 4) to test physical address, set grub to (intel/amd)_iommu_mode=off
 *    4.1) add " memmap=1G\\\$4G" into grub, update-grub, reboot
 *    4.2) add "carvedout_addr=0x100000000 carvedout_size=0x40000000" in insmod cmd
 */
int aie4_hello_test(struct amdxdna_dev_hdl *ndev, struct amdxdna_ctx *ctx)
{
	DECLARE_AIE4_MSG(aie4_create_hw_context, AIE4_MSG_OP_CREATE_HW_CONTEXT);
	struct amdxdna_dev *xdna = ndev->xdna;
	struct amdxdna_ctx_priv *nctx = ctx->priv;
	const struct amdxdna_dev_priv *npriv = xdna->dev_info->dev_priv;
	int ret;

	u32 out_magic = 0;
	u32 size = nctx->umq_bo->mem.size / sizeof(u32); //size is in words
	u32 step = size / 4; //only 4 writes, 0, 1/4, 1/2, 3/4
	int retry = 30;
	u64 data_ptr = (u64)amdxdna_gem_vmap(nctx->umq_bo);
	u32 idx;

	XDNA_WARN(xdna, "test mem size 0x%x", size);

	/*
	 * data_ptr is already mapped. write IN_MAGIC onto
	 * offset 0:
	 * offset 1:
	 * offset step:
	 */
	for (idx = 0; idx < size; idx += step) {
		*((u32 *)data_ptr + idx) = IN_MAGIC;
		XDNA_WARN(xdna, "write magic 0x%x to index %d",  *((u32 *)data_ptr + idx),  idx);
	}
	*((u32 *)data_ptr + 1) = size;
	XDNA_WARN(xdna, "write size 0x%x to index %d",  *((u32 *)data_ptr + 1),  1);

	req.partition_id = ndev->partition_id;
	req.request_num_tiles = 3; //set to 3 for now
	req.hsa_addr_high = upper_32_bits(amdxdna_gem_dev_addr(nctx->umq_bo));
	req.hsa_addr_low = lower_32_bits(amdxdna_gem_dev_addr(nctx->umq_bo));

	XDNA_DBG(xdna, "partition_id %d, tiles %d, hsa[0x%x 0x%x]",
		 req.partition_id,
		 req.request_num_tiles,
		 req.hsa_addr_high,
		 req.hsa_addr_low);

	ret = aie4_send_msg_wait(ndev, &msg);
	if (ret) {
		XDNA_ERR(xdna, "create ctx failed %d", ret);
		goto test_done;
	}

	//need to send doorbell to trigger the HWS init CERT
	XDNA_WARN(xdna, "ring first doorbell to notify mpnpu fw to setup CERT");
	writel(0x0, ndev->rbuf_base + npriv->doorbell_off + 0x40000);

	for (; retry > 0; retry--) {
		msleep(2000);
		//This is the last step we write a magic before
		XDNA_WARN(xdna, "check idx %d", (idx - step));
		if (*((u32 *)data_ptr + idx - step) == OUT_MAGIC)
			break;
	}

	if (retry == 0) {
		XDNA_ERR(xdna, "TIMEOUT");
		ret = -ETIME;
	} else {
		for (u32 i = 0; i < size; i += step) {
			out_magic = *((u32 *)data_ptr + i);
			XDNA_WARN(xdna, "[%d] write 0x%x, read back 0x%x", i, out_magic, OUT_MAGIC);
			if (out_magic != OUT_MAGIC) {
				XDNA_ERR(xdna, "[%d] FAIL", i);
				ret = -EIO;
			}
		}
	}

	XDNA_WARN(xdna, ">> %s <<", ret ? "FAIL" : "PASS");

test_done:
	/* Test done, always return ebusy to prevent consequence damage in the driver */
	return -EBUSY;
}
#endif // endif UMQ_HELLO_TEST
