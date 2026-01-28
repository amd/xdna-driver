// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023-2026, Advanced Micro Devices, Inc. All rights reserved.

#ifndef HWQ_KMQ_H
#define HWQ_KMQ_H

#include "../hwq.h"

namespace shim_xdna {

class hwq_kmq : public hwq
{
public:
  hwq_kmq(const device& device);
  ~hwq_kmq();

  bo_id
  get_queue_bo() const override;
};

}

#endif
