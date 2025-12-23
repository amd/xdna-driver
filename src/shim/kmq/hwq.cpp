// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "hwq.h"

namespace shim_xdna {

hwq_kmq::
hwq_kmq(const device& device) : hwq(device)
{
  shim_debug("Created KMQ HW queue");
}

hwq_kmq::
~hwq_kmq()
{
  shim_debug("Destroying KMQ HW queue");
}

bo_id
hwq_kmq::
get_queue_bo() const
{
  return { AMDXDNA_INVALID_BO_HANDLE, AMDXDNA_INVALID_BO_HANDLE };
}

}
