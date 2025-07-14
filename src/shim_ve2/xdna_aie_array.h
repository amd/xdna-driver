// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef XDNA_AIE_H__
#define XDNA_AIE_H__

#include "core/edge/common/aie_parser.h"
#include "core/common/device.h"
extern "C" {
#include <xaiengine.h>
}

namespace xaiefal
{
   class XAieRsc;
}

namespace shim_xdna_edge {

class xdna_hwctx;

class xdna_aie_array {

public:
  ~xdna_aie_array();
	xdna_aie_array(const xrt_core::device* device);
   xdna_aie_array(const xrt_core::device* device, const xdna_hwctx* hwctx_obj);
	XAie_DevInst *get_dev();
   adf::driver_config get_driver_config_hwctx(const xrt_core::device* device, const xdna_hwctx* hwctx);
private:
  int num_cols;
  int fd;
  XAie_DevInst* dev_inst;         // AIE Device Instance pointer
  // XAie_InstDeclare(DevInst, &ConfigPtr) is the interface
  // to initialize DevInst by the AIE driver. But it does not
  // work here because we can not make it as a member of Aie
  // class to maintain its life cylce. So we declair it here.
  //
  // Note: need to evolve when XAie_InstDecalare() evolves.
  XAie_DevInst dev_inst_obj;
};

} //namespace shim_xdna_edge

#endif
