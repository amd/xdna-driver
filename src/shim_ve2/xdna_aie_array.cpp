// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/optional.hpp>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "core/edge/common/aie_parser.h"
#include "core/edge/user/hwctx_object.h"
#include "xaiengine/xlnx-ai-engine.h"
#include "xdna_aie_array.h"
#include "xdna_device.h"
#include "xdna_hwctx.h"

namespace shim_xdna_edge {

namespace pt = boost::property_tree;
void read_aie_metadata(const char* data, size_t size, pt::ptree& aie_project)
{
  std::stringstream aie_stream;
  aie_stream.write(data,size);
  pt::read_json(aie_stream,aie_project);
}

adf::driver_config
get_driver_config(const pt::ptree& aie_meta)
{
  adf::driver_config driver_config;
  driver_config.hw_gen = aie_meta.get<uint8_t>("aie_metadata.driver_config.hw_gen");
  driver_config.base_address = aie_meta.get<uint64_t>("aie_metadata.driver_config.base_address");
  driver_config.column_shift = aie_meta.get<uint8_t>("aie_metadata.driver_config.column_shift");
  driver_config.row_shift = aie_meta.get<uint8_t>("aie_metadata.driver_config.row_shift");
  driver_config.num_columns = aie_meta.get<uint8_t>("aie_metadata.driver_config.num_columns");
  driver_config.num_rows = aie_meta.get<uint8_t>("aie_metadata.driver_config.num_rows");
  driver_config.shim_row = aie_meta.get<uint8_t>("aie_metadata.driver_config.shim_row");
  if (!aie_meta.get_optional<uint8_t>("aie_metadata.driver_config.mem_tile_row_start") ||
      !aie_meta.get_optional<uint8_t>("aie_metadata.driver_config.mem_tile_num_rows")) {
    driver_config.mem_row_start = aie_meta.get<uint8_t>("aie_metadata.driver_config.reserved_row_start");
    driver_config.mem_num_rows = aie_meta.get<uint8_t>("aie_metadata.driver_config.reserved_num_rows");
  }
  else {
    driver_config.mem_row_start = aie_meta.get<uint8_t>("aie_metadata.driver_config.mem_tile_row_start");
    driver_config.mem_num_rows = aie_meta.get<uint8_t>("aie_metadata.driver_config.mem_tile_num_rows");
  }
  driver_config.aie_tile_row_start = aie_meta.get<uint8_t>("aie_metadata.driver_config.aie_tile_row_start");
  driver_config.aie_tile_num_rows = aie_meta.get<uint8_t>("aie_metadata.driver_config.aie_tile_num_rows");
  return driver_config;
}

xdna_aie_array::
xdna_aie_array(const xrt_core::device* device)
{
  dev_inst_obj = {0};
  dev_inst = nullptr;
  adf::driver_config driver_config = xrt_core::edge::aie::get_driver_config(device);

  XAie_SetupConfig(ConfigPtr,
      driver_config.hw_gen,
      driver_config.base_address,
      driver_config.column_shift,
      driver_config.row_shift,
      driver_config.num_columns,
      driver_config.num_rows,
      driver_config.shim_row,
      driver_config.mem_row_start,
      driver_config.mem_num_rows,
      driver_config.aie_tile_row_start,
      driver_config.aie_tile_num_rows);

  int RC = XAie_GetPartitionFdList(&dev_inst_obj);

  if (RC != XAIE_OK) 
   throw xrt_core::error(RC,"XAie_GetPartitionFdList failed \n");

  XAie_List *NodePtr;
  XAie_PartitionList *ListNode;

  NodePtr = (XAie_List *)&dev_inst_obj.PartitionList.Next->Next;

  ListNode = (XAie_PartitionList *)XAIE_CONTAINER_OF(NodePtr, XAie_PartitionList, Node);

  int aie_part_fd = ListNode->PartitionFd;

  //int aie_part_fd = fd;

  if (aie_part_fd < 0)
    throw xrt_core::error(aie_part_fd,"fd is NEGATIVE\n");

  fd = aie_part_fd;
  ConfigPtr.PartProp.Handle = fd;

  AieRC rc;
  if ((rc = XAie_CfgInitialize(&dev_inst_obj, &ConfigPtr)) != XAIE_OK)
    throw xrt_core::error(-EINVAL, "Failed to initialize AIE configuration: " + std::to_string(rc));

  dev_inst = &dev_inst_obj;
}

xdna_aie_array::
xdna_aie_array(const xrt_core::device* device, const xdna_hwctx* hwctx_obj)
{
  dev_inst_obj = {0};
  dev_inst = nullptr;
  adf::driver_config driver_config = get_driver_config_hwctx(device, hwctx_obj);

  XAie_SetupConfig(ConfigPtr,
      driver_config.hw_gen,
      driver_config.base_address,
      driver_config.column_shift,
      driver_config.row_shift,
      driver_config.num_columns,
      driver_config.num_rows,
      driver_config.shim_row,
      driver_config.mem_row_start,
      driver_config.mem_num_rows,
      driver_config.aie_tile_row_start,
      driver_config.aie_tile_num_rows);

  auto part_info = hwctx_obj->get_partition_info();
  if (part_info.partition_id != xrt_core::edge::aie::full_array_id) {
    AieRC rc1;
    if ((rc1 = XAie_SetupPartitionConfig(&dev_inst_obj, part_info.base_address, part_info.start_column, part_info.num_columns)) != XAIE_OK)
      throw xrt_core::error(-EINVAL, "Failed to setup AIE Partition: " + std::to_string(rc1));
  }

  int RC = XAie_GetPartitionFdList(&dev_inst_obj);

  if (RC != XAIE_OK) 
   throw xrt_core::error(RC,"XAie_GetPartitionFdList failed \n");

  XAie_List *NodePtr;
  XAie_PartitionList *ListNode;

  NodePtr = (XAie_List *)&dev_inst_obj.PartitionList.Next->Next;

  ListNode = (XAie_PartitionList *)XAIE_CONTAINER_OF(NodePtr, XAie_PartitionList, Node);

  int aie_part_fd = ListNode->PartitionFd;

  if (aie_part_fd < 0)
    throw xrt_core::error(aie_part_fd,"fd is NEGATIVE\n");

  fd = aie_part_fd;
  ConfigPtr.PartProp.Handle = fd;

  AieRC rc;
  if ((rc = XAie_CfgInitialize(&dev_inst_obj, &ConfigPtr)) != XAIE_OK)
    throw xrt_core::error(-EINVAL, "Failed to initialize AIE configuration: " + std::to_string(rc));

  dev_inst = &dev_inst_obj;
}

xdna_aie_array::
~xdna_aie_array()
{
  if (dev_inst)
    XAie_Finish(dev_inst);
}

XAie_DevInst*
xdna_aie_array::
get_dev()
{
  if (!dev_inst)
    throw xrt_core::error(-EINVAL, "AIE is not initialized");

  return dev_inst;
}

adf::driver_config
xdna_aie_array::
get_driver_config_hwctx(const xrt_core::device* device, const xdna_hwctx* hwctx)
{
  auto xclbin_uuid = hwctx ? hwctx->get_xclbin_uuid() : xrt::uuid();
  auto data = device->get_axlf_section(AIE_TRACE_METADATA, xclbin_uuid);
  if (!data.first || !data.second)
    return {};

  pt::ptree aie_meta;
  read_aie_metadata(data.first, data.second, aie_meta);
  return get_driver_config(aie_meta);
}

} //namespace shim_xdna_edge

