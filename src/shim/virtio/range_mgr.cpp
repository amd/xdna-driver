// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include "range_mgr.h"
#include "../shim_debug.h"

#include <iostream>

namespace shim_xdna {

range_mgr::
range_mgr(uint64_t start, uint64_t end)
{
  m_free_ranges.insert({start, end});
}

uint64_t
range_mgr::
alloc(uint64_t size)
{
  for (auto it = m_free_ranges.begin(); it != m_free_ranges.end(); ++it) {
    if (it->m_end - it->m_start + 1 < size)
      continue;

    uint64_t alloc_start = it->m_start;
    uint64_t alloc_end = alloc_start + size - 1;
    uint64_t it_end = it->m_end;
    m_allocated_ranges.insert({alloc_start, alloc_end});
          
    // Remove the used part from m_free_ranges
    m_free_ranges.erase(it);
    if (alloc_end < it_end)
      m_free_ranges.insert({alloc_end + 1, it_end});

    return alloc_start;
  }
  shim_err(ENOMEM, "Not enough ranges");
}

void
range_mgr::
free(uint64_t start)
{
  auto it = m_allocated_ranges.find({start, start+1});
  if (it == m_allocated_ranges.end())
    shim_err(ENOENT, "Freeing range not alloc'ed before");
  auto end = it->m_end;

  m_allocated_ranges.erase(it);

  // Merge with adjacent free ranges
  range new_free{start, end};

  auto after = m_free_ranges.upper_bound(new_free);
  auto before = (after == m_free_ranges.begin()) ? m_free_ranges.end() : std::prev(after);

  if (after != m_free_ranges.end() && after->m_start == end + 1) {
    new_free.m_end = after->m_end;
    m_free_ranges.erase(after);
  }

  if (before != m_free_ranges.end() && before->m_end + 1 == start) {
    new_free.m_start = before->m_start;
    m_free_ranges.erase(before);
  }

  m_free_ranges.insert(new_free);
}

void
range_mgr::
print(void)
{
  std::cout << "Free Ranges: ";
  for (const auto& range : m_free_ranges)
    std::cout << "[" << range.m_start << ", " << range.m_end << "] ";
  std::cout << "\n";

  std::cout << "Allocated Ranges: ";
  for (const auto& range : m_allocated_ranges)
    std::cout << "[" << range.m_start << ", " << range.m_end << "] ";
  std::cout << "\n\n";
}

} // namespace shim_xdna

