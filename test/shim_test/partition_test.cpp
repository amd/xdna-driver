// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

//
// AIE4 partition placement tests (npu3b / T20).
//
// On AIE4, create_hw_context() only submits the context to the RPU firmware;
// the firmware owns scheduling, so there is nothing to "wait" on from the
// host - a valid request simply succeeds once it is sent.  What we can verify
// is placement: a partition is described purely by its column geometry
// (start column + width), and the full-ELF create path only needs that column
// count - not an ELF - so these tests drive width/start directly through
// create_hw_context() and do not depend on any ELF file.
//
// Covered:
//   * full array (24 cols) pinned at start column 0        -> fits, succeeds.
//   * full array pinned at a non-zero start column         -> cannot fit, fails.
//   * overlapping partitions of different widths           -> second fails.
//   * identical partitions (same start + width)            -> share, succeed.
//   * non-overlapping partitions                           -> both succeed.
//

#include "core/common/device.h"
#include "core/common/query_requests.h"
#include "core/common/shim/hwctx_handle.h"

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

using namespace xrt_core;
using arg_type = const std::vector<uint64_t>;

namespace {

constexpr uint32_t FULL_ARRAY_COLS = 24;      // full-array partition width
constexpr uint32_t NONZERO_START_COL = 4;     // any non-zero start won't fit a full array

uint32_t
total_columns(device* dev)
{
  return device_query<query::aie_tiles_stats>(dev).cols;
}

// Create a partition of an arbitrary column width.  start_col < 0 means "no
// start column" (flexible: the firmware places it); a non-negative value pins
// the partition to that column.  The full-ELF create path only needs the
// column count (partition_size), not an ELF, so this drives geometry directly
// - no per-width ELF is required.
std::unique_ptr<hwctx_handle>
create_partition(device* dev, uint32_t width, int start_col)
{
  xrt::hw_context::qos_type qos{
    {"gops", 100},
    {"priority", 0x180},
  };
  if (start_col >= 0)
    qos["start_col"] = static_cast<uint32_t>(start_col);
  return dev->create_hw_context(width, qos, xrt::hw_context::access_mode::shared);
}

} // namespace

//
// A full-array partition pinned at start column 0 fits and is created
// successfully; its reported geometry is the full 24 columns at column 0.
//
void
TEST_partition_full_at_col0(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  if (total_columns(dev) < FULL_ARRAY_COLS) {
    std::cout << "  device has " << total_columns(dev) << " columns (< " << FULL_ARRAY_COLS
              << "); skipping full-array test" << std::endl;
    return;
  }

  auto ctx = create_partition(dev, FULL_ARRAY_COLS, 0);

  auto parts = device_query<query::aie_partition_info>(dev);
  auto me = static_cast<int64_t>(getpid());
  bool found = false;
  for (const auto& p : parts) {
    if (p.pid != me)
      continue; // ignore contexts owned by other processes
    found = true;
    if (p.num_cols != FULL_ARRAY_COLS)
      throw std::runtime_error("full partition (ctx " + p.metadata.id + ") reports num_col " +
        std::to_string(p.num_cols) + ", expected " + std::to_string(FULL_ARRAY_COLS));
    if (p.start_col != 0)
      throw std::runtime_error("full partition (ctx " + p.metadata.id + ") reports start_col " +
        std::to_string(p.start_col) + ", expected 0");
  }
  if (!found)
    throw std::runtime_error("no partition reported for this process");

  std::cout << "  full-array partition created at start_col 0, num_col == "
            << FULL_ARRAY_COLS << std::endl;
}

//
// A full-array partition pinned at a non-zero start column cannot fit and is
// rejected.  Registered as a negative test: the harness expects the create to
// throw.
//
void
TEST_partition_full_at_nonzero_col(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  if (total_columns(dev) < FULL_ARRAY_COLS) {
    // Cannot exercise the full-array case; force the negative expectation by
    // throwing (a device this small can't seat a full array anywhere).
    throw std::runtime_error("device too small for a full-array partition");
  }

  auto ctx = create_partition(dev, FULL_ARRAY_COLS, NONZERO_START_COL);
  std::cout << "  unexpected: full-array create at start_col " << NONZERO_START_COL
            << " succeeded" << std::endl;
}

//
// Two partitions whose columns partially overlap with different widths cannot
// both be placed: a 4-wide partition at column 4 (cols 4-7) plus an 8-wide
// partition at column 4 (cols 4-11) conflict, so the second create fails.
//
void
TEST_partition_overlap_conflict(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();

  auto p1 = create_partition(dev, 4, 4); // cols 4-7

  bool threw = false;
  try {
    auto p2 = create_partition(dev, 8, 4); // cols 4-11, overlaps p1
  } catch (const std::exception& e) {
    threw = true;
    std::cout << "  overlapping partition (start 4, width 8) correctly rejected: "
              << e.what() << std::endl;
  }
  if (!threw)
    throw std::runtime_error(
      "expected overlapping partition (start 4, width 8) to fail, but it succeeded");
}

//
// Two partitions with identical geometry (start column 4, width 4) share the
// same firmware partition and both create successfully.
//
void
TEST_partition_identical_ok(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();

  auto p1 = create_partition(dev, 4, 4);
  auto p2 = create_partition(dev, 4, 4);

  std::cout << "  two identical partitions (start 4, width 4) created" << std::endl;
}

//
// Two partitions that do not overlap - a 4-wide partition at column 4
// (cols 4-7) and a 4-wide partition at column 8 (cols 8-11) - both create
// successfully.
//
void
TEST_partition_adjacent_ok(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();

  auto p1 = create_partition(dev, 4, 4); // cols 4-7
  auto p2 = create_partition(dev, 4, 8); // cols 8-11

  std::cout << "  non-overlapping partitions (start 4 width 4, start 8 width 4) created"
            << std::endl;
}

//
// Probe whether a 6-column partition is accepted at all, independent of where
// it is placed: create a single one with no start column (flexible placement).
// This isolates "is width 6 itself the problem?" from any start-column rules.
//
void
TEST_partition_width6_flexible(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  try {
    auto p = create_partition(dev, 6, -1); // -1 == no start column
    std::cout << "  width 6, no start column: created OK" << std::endl;
  } catch (const std::exception& e) {
    std::cout << "  width 6, no start column: FAILED - " << e.what() << std::endl;
  }
}

//
// Probe which start columns the firmware accepts for a single 6-column
// partition, scanning start columns 0..4.  Each attempt is created and
// destroyed on its own, and the outcome is reported per start column rather
// than asserting a fixed expectation.
//
void
TEST_partition_width6_start_scan(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  const int starts[] = { 0, 1, 2, 3, 4 };

  for (int sc : starts) {
    try {
      auto p = create_partition(dev, 6, sc);
      std::cout << "  width 6, start_col " << sc << ": created OK" << std::endl;
    } catch (const std::exception& e) {
      std::cout << "  width 6, start_col " << sc << ": FAILED - " << e.what() << std::endl;
    }
  }
}
