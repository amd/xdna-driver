// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#include <linux/vmalloc.h>
#include <linux/firmware.h>

#include "amdxdna_drv.h"
#include "amdxdna_axlf.h"
#include "amdxdna_xclbin.h"
#include "npu_pci.h"
#ifdef AMDXDNA_DEVEL
#include "amdxdna_devel.h"
#endif

#define XCLBIN_V2 "xclbin2"

/*
 * The maximum number of PDIs, use this value is considering multiple factors:
 * firmware can only handle this many of PDIs per context or register xclbin
 */
#define XCLBIN_MAX_NUM_PDIS	16
/* The maximum supported size of PDI image is 64MB. This is big enough. */
#define XCLBIN_MAX_PDI_SIZE     (64 * 0x100000)

static inline const
uuid_t *xclbin_get_uuid(const struct axlf *axlf)
{
	return (uuid_t *)axlf->header.uuid;
}

static const struct axlf_section_header *
xclbin_get_section_hdr(const struct axlf *axlf, enum axlf_section_kind kind)
{
	int i;

	for (i = 0; i < axlf->header.num_sections; i++) {
		if (axlf->sections[i].section_kind == kind)
			return &axlf->sections[i];
	}

	return NULL;
}

static enum pdi_type
convert_to_pdi_type(enum CDO_TYPE type)
{
	enum pdi_type ret;

	switch (type) {
	case CT_PRIMARY:
		ret = PDI_TYPE_PRIMARY;
		break;
	case CT_LITE:
		ret = PDI_TYPE_LITE;
		break;
	default:
		ret = MAX_PDI_TYPE;
	}

	return ret;
}

static inline void
amdxdna_pdi_cleanup(struct amdxdna_dev *xdna, struct amdxdna_pdi *pdis, int num_pdis)
{
	int i;

	for (i = 0; i < num_pdis; i++) {
		if (!pdis[i].image)
			continue;

#ifdef AMDXDNA_DEVEL
		if (iommu_mode == AMDXDNA_IOMMU_BYPASS)
			continue;
#endif
		dma_free_noncoherent(&xdna->pdev->dev, pdis[i].size, pdis[i].image,
				     pdis[i].addr, DMA_TO_DEVICE);

		XDNA_DBG(xdna, "PDI id %d free", pdis[i].id);
		ida_free(&xdna->pdi_ida, pdis[i].id);
		kfree(pdis[i].dpu_ids);
	}
}

static int
amdxdna_pdi_parse(struct amdxdna_dev *xdna, struct amdxdna_pdi *pdis,
		  int num_pdis, const struct aie_partition *part)
{
	const struct aie_pdi *pdi_array;
	int ret = 0;
	int i;

	pdi_array = get_array(part, &part->aie_pdis);
	for (i = 0; i < num_pdis; i++) {
		const struct cdo_group *cdo_array;
		dma_addr_t pdi_dev_addr;
		size_t dpu_ids_bytes;
		const u8 *pdi_image;
		u8 *pdi_cpu_addr;
		u64 *dpu_ids;
		u32 size;

		pdi_image = get_array(part, &pdi_array[i].pdi_image);
		cdo_array = get_array(part, &pdi_array[i].cdo_groups);
		size = pdi_array[i].pdi_image.size;

#ifdef AMDXDNA_DEVEL
		if (iommu_mode == AMDXDNA_IOMMU_BYPASS) {
			ret = -EOPNOTSUPP;
			goto cleanup_pdi_blobs;
		}
#endif
		pdi_cpu_addr = dma_alloc_noncoherent(&xdna->pdev->dev, size, &pdi_dev_addr,
						     DMA_TO_DEVICE, GFP_KERNEL);
		if (!pdi_cpu_addr) {
			ret = -ENOMEM;
			goto cleanup_pdi_blobs;
		}
		memcpy(pdi_cpu_addr, pdi_image, size);

		pdis[i].image = pdi_cpu_addr;
		pdis[i].addr = pdi_dev_addr;
		pdis[i].size = size;
		/* Only support 1 element in cdo_groups for now */
		pdis[i].type = convert_to_pdi_type(cdo_array[0].cdo_type);
		pdis[i].id = ida_alloc(&xdna->pdi_ida, GFP_KERNEL);
		if (pdis[i].id < 0) {
			XDNA_ERR(xdna, "Cannot allocate PDI id");
			ret = pdis[i].id;
			goto cleanup_pdi_blobs;
		}
		XDNA_DBG(xdna, "PDI id %d allocated", pdis[i].id);
		pdis[i].num_dpu_ids = cdo_array[0].dpu_kernel_ids.size;
		dpu_ids_bytes = sizeof(u64) * pdis[i].num_dpu_ids;

		dpu_ids = kmalloc(dpu_ids_bytes, GFP_KERNEL);
		if (!dpu_ids) {
			ret = -ENOMEM;
			goto cleanup_pdi_blobs;
		}
		memcpy(dpu_ids, get_array(part, &cdo_array[0].dpu_kernel_ids), dpu_ids_bytes);
		pdis[i].dpu_ids = dpu_ids;
		uuid_copy(&pdis[i].uuid, (uuid_t *)pdi_array[i].uuid);
	}

	return 0;

cleanup_pdi_blobs:
	amdxdna_pdi_cleanup(xdna, pdis, num_pdis);
	return ret;
}

static int amdxdna_xclbin_get_pdi_id(struct amdxdna_dev *xdna,
				     struct amdxdna_xclbin *xclbin, u32 dpu_id)
{
	struct amdxdna_partition *part = &xclbin->partition;
	int pdi_id = -1;
	int i, j;

	for (i = 0; i < part->num_pdis; i++) {
		struct amdxdna_pdi *pdi = &part->pdis[i];

		/* Return primary PDI id if dpu id is not found */
		if (pdi->type == PDI_TYPE_PRIMARY)
			pdi_id = pdi->id;

		for (j = 0; j < pdi->num_dpu_ids; j++) {
			if (pdi->dpu_ids[j] != dpu_id)
				continue;

			pdi_id = pdi->id;
			goto out;
		}
	}

out:
	XDNA_DBG(xdna, "return id %d", pdi_id);
	return pdi_id;
}

static int
amdxdna_xclbin_parse_iplayout(struct amdxdna_dev *xdna, const struct axlf *axlf,
			      struct amdxdna_xclbin *xclbin)
{
	const struct axlf_section_header *hdr;
	const struct ip_layout *ips;
	struct amdxdna_cu *cu;
	int i, cu_index = 0;

	hdr = xclbin_get_section_hdr(axlf, IP_LAYOUT);
	if (!hdr) {
		XDNA_ERR(xdna, "IP_LAYOUT section not found");
		return -ENODATA;
	}
	ips = get_section(axlf, hdr);

	xclbin->num_cus = 0;
	for (i = 0; i < ips->count; i++) {
		const struct ip_data *ip;

		ip = &ips->ip_data[i];
		if (ip->type == IP_PS_KERNEL && ip->sub_type == ST_DPU)
			xclbin->num_cus++;
	}

	cu = kcalloc(xclbin->num_cus, sizeof(*cu), GFP_KERNEL);
	if (!cu)
		return -ENOMEM;

	for (i = 0; i < ips->count; i++) {
		const struct ip_data *ip;
		int pdi_id;

		ip = &ips->ip_data[i];
		if (ip->type != IP_PS_KERNEL || ip->sub_type != ST_DPU)
			continue;

		strscpy(cu[cu_index].name, ip->name, sizeof(cu[cu_index].name));
		cu[cu_index].func = ip->functional;
		pdi_id = amdxdna_xclbin_get_pdi_id(xdna, xclbin, ip->dpu_kernel_id);
		if (pdi_id < 0) {
			XDNA_WARN(xdna, "Cannot find PDI for CU %s DPU ID %d",
				  cu[cu_index].name, ip->dpu_kernel_id);

			continue;
		}

		XDNA_DBG(xdna, "DPU ID(0x%x) -> PDI ID %d", ip->dpu_kernel_id, pdi_id);
		cu[cu_index].pdi_id = pdi_id;
		cu[cu_index].dpu_id = ip->dpu_kernel_id;
		cu[cu_index].index = cu_index;
		cu_index++;
	}
	xclbin->cu = cu;

	return 0;
}

static int
amdxdna_xclbin_parse_aie(struct amdxdna_dev *xdna, const struct axlf *axlf,
			 struct amdxdna_xclbin *xclbin)
{
	const struct axlf_section_header *hdr;
	struct amdxdna_partition *xdna_part;
	const struct aie_partition *part;
	struct amdxdna_pdi *pdis;
	size_t start_cols_bytes;
	u16 *part_start_cols;
	int ret;

	hdr = xclbin_get_section_hdr(axlf, AIE_PARTITION);
	if (unlikely(!hdr)) {
		XDNA_ERR(xdna, "AIE_PARTITION not found, data corrupted?");
		return -EINVAL;
	}

	xdna_part = &xclbin->partition;

	part = get_section(axlf, hdr);
	pdis = kcalloc(part->aie_pdis.size, sizeof(*pdis), GFP_KERNEL);
	if (!pdis) {
		XDNA_ERR(xdna, "No memory for PDIs");
		return -ENOMEM;
	}

	ret = amdxdna_pdi_parse(xdna, pdis, part->aie_pdis.size, part);
	if (ret) {
		XDNA_ERR(xdna, "PDI parse failed");
		goto free_pdis;
	}

	xdna_part->pdis = pdis;
	xdna_part->num_pdis = part->aie_pdis.size;
	xdna_part->ncols = part->info.column_width;
	xdna_part->nparts = part->info.start_columns.size;
	xdna_part->ops = part->operations_per_cycle;

	start_cols_bytes = part->info.start_columns.size * sizeof(u16);

	part_start_cols = kmalloc(start_cols_bytes, GFP_KERNEL);
	if (!part_start_cols) {
		ret = -ENOMEM;
		goto free_parsed_pdi;
	}

	memcpy(part_start_cols, get_array(part, &part->info.start_columns), start_cols_bytes);
	xdna_part->start_cols = part_start_cols;

	return 0;

free_parsed_pdi:
	amdxdna_pdi_cleanup(xdna, pdis, part->aie_pdis.size);
free_pdis:
	kfree(pdis);
	return ret;
}

static void
amdxdna_xclbin_mem_free(struct amdxdna_dev *xdna, struct amdxdna_xclbin *xclbin)
{
	struct amdxdna_partition *part;

	kfree(xclbin->cu);
	part = &xclbin->partition;
	amdxdna_pdi_cleanup(xdna, part->pdis, part->num_pdis);
	kfree(part->start_cols);
	kfree(part->pdis);
}

static int
amdxdna_xclbin_parse(struct amdxdna_dev *xdna, const struct axlf *axlf,
		     struct amdxdna_xclbin *xclbin)
{
	int ret;

	ret = amdxdna_xclbin_parse_aie(xdna, axlf, xclbin);
	if (ret) {
		XDNA_ERR(xdna, "parse AIE section failed, ret %d", ret);
		return ret;
	}

	/* Parse iplayout must be after parse xdna */
	ret = amdxdna_xclbin_parse_iplayout(xdna, axlf, xclbin);
	if (ret) {
		amdxdna_xclbin_mem_free(xdna, xclbin);
		XDNA_ERR(xdna, "parse IP_LAYOUT section failed, ret %d", ret);
		return ret;
	}

	return 0;
}

static void
amdxdna_xclbin_release(struct kref *ref)
{
	struct amdxdna_xclbin *xclbin;
	struct amdxdna_dev *xdna;

	xclbin = container_of(ref, struct amdxdna_xclbin, ref);
	xdna = xclbin->xdna;

	XDNA_DBG(xdna, "releasing XCLBIN, UUID %pUb", &xclbin->uuid);
	if (npu_unregister_pdis(xdna->dev_handle, xclbin))
		XDNA_WARN(xdna, "unregister PDI failed");

	list_del(&xclbin->entry);

	amdxdna_xclbin_mem_free(xdna, xclbin);
	kfree(xclbin);
}

static struct amdxdna_xclbin *amdxdna_xclbin_get(struct amdxdna_dev *xdna, const uuid_t *uuid)
{
	struct amdxdna_xclbin *xclbin;

	list_for_each_entry(xclbin, &xdna->xclbin_list, entry) {
		if (uuid_equal(uuid, &xclbin->uuid)) {
			kref_get(&xclbin->ref);
			return xclbin;
		}
	}

	return NULL;
}

static int amdxdna_xclbin_register(struct amdxdna_dev *xdna, const struct axlf *axlf,
				   size_t size, struct amdxdna_xclbin **xclbin)
{
	struct amdxdna_xclbin *xp;
	int ret;

	xp = kzalloc(sizeof(*xp), GFP_KERNEL);
	if (!xp)
		return -ENOMEM;

	uuid_copy(&xp->uuid, xclbin_get_uuid(axlf));
	xp->xdna = xdna;

	ret = amdxdna_xclbin_parse(xdna, axlf, xp);
	if (ret) {
		XDNA_ERR(xdna, "Parse XCLBIN failed, ret %d", ret);
		goto xclbin_free;
	}

	ret = npu_register_pdis(xdna->dev_handle, xp);
	if (ret) {
		XDNA_ERR(xdna, "register xclbin failed, ret %d", ret);
		goto xclbin_mem_free;
	}

	kref_init(&xp->ref);

	/* Finally, add XCLBIN cache to the XCLBIN list */
	list_add_tail(&xp->entry, &xdna->xclbin_list);

	*xclbin = xp;
	XDNA_DBG(xdna, "cached XCLBIN, UUID %pUb", &xp->uuid);
	return 0;

xclbin_mem_free:
	amdxdna_xclbin_mem_free(xdna, xp);
xclbin_free:
	kfree(xclbin);
	return ret;
}

int amdxdna_xclbin_load(struct amdxdna_dev *xdna, uuid_t *uuid,
			struct amdxdna_xclbin **xclbin)
{
	const struct firmware *fw;
	const struct axlf *axlf;
	char xclbin_path[70];
	int ret = 0;

	*xclbin = amdxdna_xclbin_get(xdna, uuid);
	if (*xclbin) {
		XDNA_DBG(xdna, "XCLBIN existed, no need to re-register");
		goto out;
	}

	snprintf(xclbin_path, sizeof(xclbin_path), "amdnpu/%x/%pUb.xclbin",
		 xdna->pdev->device, uuid);

	ret = request_firmware(&fw, xclbin_path, &xdna->pdev->dev);
	if (ret) {
		XDNA_ERR(xdna, "Failed to load xclbin firmware, UUID %pUb", uuid);
		goto out;
	}
	XDNA_DBG(xdna, "Firmware %s loaded", xclbin_path);

	axlf = (const struct axlf *)fw->data;
	ret = amdxdna_xclbin_register(xdna, axlf, fw->size, xclbin);

	release_firmware(fw);
out:
	return ret;
}

void amdxdna_xclbin_unload(struct amdxdna_dev *xdna, struct amdxdna_xclbin *xclbin)
{
	XDNA_DBG(xdna, "put XCLBIN, UUID %pUb", &xclbin->uuid);
	kref_put(&xclbin->ref, amdxdna_xclbin_release);
}

#ifdef AMDXDNA_DEVEL
/* Below are HACK: driver gets xclbin from user directly */
static inline u64
xclbin_get_length(const struct axlf *axlf)
{
	return axlf->header.length;
}

static int amdxdna_validate_axlf(struct amdxdna_dev *xdna, const struct axlf *axlf)
{
	if (memcmp(axlf->magic, XCLBIN_V2, sizeof(XCLBIN_V2))) {
		XDNA_ERR(xdna, "Invalid xclbin magic string");
		return -EINVAL;
	}

	if (uuid_is_null(xclbin_get_uuid(axlf))) {
		XDNA_ERR(xdna, "Invalid xclbin null uuid");
		return -EINVAL;
	}

	if (axlf->header.num_sections > XCLBIN_MAX_NUM_SECTION) {
		XDNA_ERR(xdna, "Too many sections");
		return -EINVAL;
	}

	return 0;
}

int amdxdna_xclbin_load_by_ptr(struct amdxdna_dev *xdna, const void __user *xclbin_p,
			       struct amdxdna_xclbin **xclbin)
{
	struct axlf header;
	size_t xclbin_size;
	struct axlf *axlf;
	int ret;

	if (copy_from_user(&header, xclbin_p, sizeof(header)))
		return -EFAULT;

	ret = amdxdna_validate_axlf(xdna, &header);
	if (ret) {
		XDNA_ERR(xdna, "validate AXLF failed, ret %d", ret);
		return ret;
	}

	*xclbin = amdxdna_xclbin_get(xdna, xclbin_get_uuid(&header));
	if (*xclbin) {
		XDNA_DBG(xdna, "XCLBIN existed, no need to re-register");
		return 0;
	}

	xclbin_size = xclbin_get_length(&header);
	axlf = vmalloc(xclbin_size);
	if (!axlf) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(axlf, xclbin_p, xclbin_size)) {
		ret = -EFAULT;
		XDNA_ERR(xdna, "copy xclbin from user failed");
		goto free_and_out;
	}

	ret = amdxdna_xclbin_register(xdna, axlf, xclbin_size, xclbin);

free_and_out:
	vfree(axlf);
out:
	return ret;

}
#endif
