/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2022-2024, Advanced Micro Devices, Inc.
 */

#ifndef _AMDXDNA_AXLF_H_
#define _AMDXDNA_AXLF_H_

#include <linux/types.h>
#include <linux/uuid.h>

#define XCLBIN_MAX_NUM_SECTION    0x10000
#define get_section(axlf, header) \
	((void *)((char *)(axlf) + (header)->section_offset))
#define get_array(aie_partition, array) \
	((void *)((char *)(aie_partition) + (array)->offset))

/*
 * xclbin file is in axlf container format. It is a structured series of
 * sections. There is a file header followed by several section
 * headers which is followed by sections. A section header points to an
 * actual section. There is an optional signature at the end. The
 * following figure illustrates a typical xclbin:
 *
 *     +---------------------+
 *     |                     |
 *     |       HEADER        |
 *     +---------------------+
 *     |   SECTION  HEADER   |
 *     |                     |
 *     +---------------------+
 *     |        ...          |
 *     |                     |
 *     +---------------------+
 *     |   SECTION  HEADER   |
 *     |                     |
 *     +---------------------+
 *     |       SECTION       |
 *     |                     |
 *     +---------------------+
 *     |         ...         |
 *     |                     |
 *     +---------------------+
 *     |       SECTION       |
 *     |                     |
 *     +---------------------+
 *     |      SIGNATURE      |
 *     |      (OPTIONAL)     |
 *     +---------------------+
 */

enum XCLBIN_MODE {
	XCLBIN_FLAT = 0,
	XCLBIN_PR,
	XCLBIN_TANDEM_STAGE2,
	XCLBIN_TANDEM_STAGE2_WITH_PR,
	XCLBIN_HW_EMU,
	XCLBIN_SW_EMU,
	XCLBIN_MODE_MAX
};

enum axlf_section_kind {
	BITSTREAM = 0,
	CLEARING_BITSTREAM,
	EMBEDDED_METADATA,
	FIRMWARE,
	DEBUG_DATA,
	SCHED_FIRMWARE,
	MEM_TOPOLOGY,
	CONNECTIVITY,
	IP_LAYOUT,
	DEBUG_IP_LAYOUT,
	DESIGN_CHECK_POINT,
	CLOCK_FREQ_TOPOLOGY,
	MCS,
	BMC,
	BUILD_METADATA,
	KEYVALUE_METADATA,
	USER_METADATA,
	DNA_CERTIFICATE,
	PDI,
	BITSTREAM_PARTIAL_PDI,
	PARTITION_METADATA,
	EMULATION_DATA,
	SYSTEM_METADATA,
	SOFT_KERNEL,
	ASK_FLASH,
	AIE_METADATA,
	ASK_GROUP_TOPOLOGY,
	ASK_GROUP_CONNECTIVITY,
	SMARTNIC,
	AIE_RESOURCES,
	OVERLAY,
	VENDER_METADATA,
	AIE_PARTITION
};

enum IP_TYPE {
	IP_MB = 0,
	IP_KERNEL,
	IP_DNASC,
	IP_DDR4_CONTROLLER,
	IP_MEM_DDR4,
	IP_MEM_HBM,
	IP_MEM_HBM_ECC,
	IP_PS_KERNEL
};

struct axlf_section_header {
	u32 section_kind;		/* Section type */
	char  section_name[16];		/* Section name */
	char  rsvd[4];
	u64 section_offset;		/* File offset of section data */
	u64 section_size;		/* Size of section data */
} __packed;

struct axlf_header {
	u64 length;			/* Total size of the xclbin file */
	u64 time_stamp;			/* Timestamp when xclbin was created */
	u64 feature_rom_timestamp;	/* TimeSinceEpoch of the featureRom */
	u16 version_patch;		/* Patch Version */
	u8  version_major;		/* Major Version */
	u8  version_minor;		/* Minor Version */
	u32 mode;			/* Xclbin mode. See enum XCLBIN_MODE */
	union {
		struct {
			u64 platform_id;/* 64 bit platform ID */
			u64 feature_id;	/* 64 bit feature ID */
		} rom;
		u8 rom_uuid[16];	/* feature ROM UUID */
	};
	unsigned char platform_vbnv[64];/* Vendor:Board:Name:Version */
	union {
		char next_axlf[16];	/* Name of next axlf file */
		u8 uuid[16];		/* uuid of this axlf */
	};
	char debug_bin[16];		/* Name of binary with debug info */
	u32 num_sections;		/* Number of section headers */
	char rsvd[4];
} __packed;

struct axlf {
	char magic[8];			/* Magic word: xclbin2\0 */
	s32 signature_length;		/* Length. -1 indicates no signature */
	u8 reserved[28];
	u8 key_block[256];		/* Signature for validation of binary */
	u64 unique_id;
	struct axlf_header header;
	struct axlf_section_header sections[];
} __packed;

/****	IP_LAYOUT SECTION ****/

/* IP Kernel */
#define IP_INT_ENABLE_MASK	  0x0001
#define IP_INTERRUPT_ID_MASK  0x00FE
#define IP_INTERRUPT_ID_SHIFT 0x1

enum IP_CONTROL {
	AP_CTRL_HS = 0,
	AP_CTRL_CHAIN,
	AP_CTRL_NONE,
	AP_CTRL_ME,
	ACCEL_ADAPTER
};

#define IP_CONTROL_MASK	 0xFF00
#define IP_CONTROL_SHIFT 0x8

enum PS_SUBTYPE {
	ST_PS = 0,
	ST_DPU,
};

enum PS_FUNCTIONAL {
	FC_DPU = 0,
	FC_PREPOST,
};

/*
 * IPs on AXI lite - their types, names, and base addresses.
 *
 * The defination of 32-bit follows IP_TYPE is based on IP_TYPE
 *   For IP_KERNEL
 *	    int_enable   : Bit  - 0x0000_0001;
 *	    interrupt_id : Bits - 0x0000_00FE;
 *	    ip_control   : Bits - 0x0000_FF00;
 *   For IP_PS_KERNEL
 *	    sub_type	 : Bits - 0x0000_0003
 *	    functional	 : Bits – 0x0000_0030;
 *	    dpu_kernel_id: Bits – 0x0FFF_0000;
 *   For IP_MEM_*
 *	    index        : Bits - 0x0000_FFFF;
 *	    pc_index     : Bits - 0x00FF_0000;
 */
struct ip_data {
	u32 type;				/* Type. See enum IP_TYPE */
	union {
		u32 properties;
		struct {
			u16 index;
			u8 pc_index;
			u8 unused;
		} indices;
		struct {
			u16 sub_type : 2;
			u16 rsvd1 : 2;
			u16 functional : 2;
			u16 rsvd2 : 10;
			u16 dpu_kernel_id : 12;
			u16 unused : 4;
		};
	};
	u64 base_address;
	u8 name[64];		/* Name of IP */
} __packed;

struct ip_layout {
	s32 count;
	s32 rsvd;
	struct ip_data ip_data[];/* ip_data array, sorted by base_address */
} __packed;

/****	AIE PARTITION SECTION ****/
struct array_offset {
	u32 size;		/* Number of elements in the array */
	u32 offset;		/* Array offset from the start of section */
};

enum CDO_TYPE {
	CT_UNKNOWN = 0,
	CT_PRIMARY = 1,
	CT_LITE    = 2,
	CT_PREPOST = 3,
};

/*
 * CDO group data
 * Prefix Syntax:
 *   mpo - member, pointer, offset
 *   This variable represents a zero terminated string
 *   that is offseted from the beginning of the section.
 *   The pointer to access the string is initialized as follows:
 *   char * pCharString = (address_of_section) + (mpo value)
 */
struct cdo_group {
	u32 mpo_name;			/* Name of the CDO group */
	u8 cdo_type;			/* CDO group type (CDO_TYPE) */
	u8 padding[3];
	u64 pdi_id;
	struct array_offset dpu_kernel_ids;	/* Array of dpu_kernel_ids */
	struct array_offset pre_cdo_groups;	/* Array of Pre CDO Group IDs */
	__u8 reserved[64];
} __packed;

struct aie_pdi {
	u8 uuid[16];				/* PDI container UUID */
	struct array_offset pdi_image;		/* PDI Image */
	struct array_offset cdo_groups;		/* Array of cdo_groups */
	u8 reserved[64];
} __packed;

struct aie_partition_info {
	u16 column_width;			/* Width of the partition */
	u8 padding[6];
	struct array_offset start_columns;	/* Array of start column identifiers */
	u8 reserved[72];
} __packed;

struct aie_partition {
	u8 schema_version;		/* Group schema version (default 0) */
	u8 padding0[3];			/* Byte alignment */
	u32 mpo_name;			/* Name of the aie_partition */
	/*
	 * Operations per cycle. Used later to create TOPS
	 * (operations_per_cycle * <AIE Clock Frequency>)
	 */
	u32 operations_per_cycle;
	u8 padding[4];
	u64 inference_fingerprint;	/* The unique hash value of the inference function */
	u64 pre_post_fingerprint;	/* The unique hash value of pre post */
	struct aie_partition_info info;	/* Partition information */
	struct array_offset aie_pdis;	/* PDI Array */
	u8 reserved[54];
} __packed;

#endif /* _AMDXDNA_AXLF_H_ */
