// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#ifndef RANGE_MGR_H
#define RANGE_MGR_H

#include <set>
#include <cstdint>

namespace shim_xdna {

struct range {
  uint64_t m_start;
  uint64_t m_end;
        
  bool operator<(const range& other) const
  {
    return m_end < other.m_start;
  }
};

class range_mgr {
public:
  range_mgr(uint64_t start, uint64_t end);

  uint64_t
  alloc(uint64_t size);

  void
  free(uint64_t start);

  void
  print(void);

private:
  std::set<range> m_free_ranges;
  std::set<range> m_allocated_ranges;
};

} // namespace shim_xdna

#endif
