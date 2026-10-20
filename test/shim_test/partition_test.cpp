// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026, Advanced Micro Devices, Inc. All rights reserved.

//
// AIE4 partition placement tests for npu12 (platform aie2ps).
//
// Ported from the npu3b tests on aie4-soc-ipc. On this branch the platform
// part is npu12 and each hardware context gets its own partition
// (partition_per_hwctx). create_hw_context() only submits the context; the
// firmware owns scheduling, so a valid request succeeds once it is sent.
// A partition is described by its column geometry (start column + width), and
// the full-ELF create path only needs that column count, so these tests drive
// width and start directly and do not depend on an ELF.
//
// npu3b was a single 24-column T20 part, so the source tests hardcoded that
// width. npu12 covers the T50/T20/T10 SKUs, so the full-array cases use the
// column count the device reports.
//
// Covered:
//   * full array pinned at start column 0                 -> fits, succeeds.
//   * full array pinned at a non-zero start column        -> cannot fit, fails.
//   * overlapping partitions of different widths          -> second fails.
//   * identical partitions (same start + width)           -> share, succeed.
//   * non-overlapping partitions                          -> both succeed.
//

#include "dev_info.h"

#include "core/common/device.h"
#include "core/common/query_requests.h"
#include "core/common/shim/hwctx_handle.h"
#include "xrt/xrt_hw_context.h"

#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

using namespace xrt_core;

namespace {

constexpr uint32_t NONZERO_START_COL = 4; // any non-zero start won't fit a full array
// Overlap / adjacent cases place an 8-wide partition at column 4 (cols 4-11).
constexpr uint32_t MIN_PLACED_COLS = 12;
constexpr uint32_t MAX_COLS = 36; // 36 col max for T50

uint32_t
total_columns(device* dev)
{
  auto cols = device_query<query::aie_tiles_stats>(dev).cols;
  if (cols > MAX_COLS) {
    const uint32_t reported = cols <= UINT16_MAX ? cols : UINT16_MAX;
    throw std::runtime_error("device reports column count above max: " +
      std::to_string(reported));
  }
  return cols;
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

void
require_columns(device* dev, uint32_t need)
{
  auto cols = total_columns(dev);
  if (cols < need)
    throw std::runtime_error("device has " + std::to_string(cols) +
      " columns, need at least " + std::to_string(need));
}

} // namespace

//
// A full-array partition pinned at start column 0 fits and is created
// successfully; its reported geometry is the device's column count at column 0.
//
void
TEST_partition_full_at_col0(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto cols = total_columns(dev);
  if (cols == 0)
    throw std::runtime_error("device reports no columns");

  auto ctx = create_partition(dev, cols, 0);

  auto parts = device_query<query::aie_partition_info>(dev);
  auto me = static_cast<int64_t>(getpid());
  bool found = false;
  for (const auto& p : parts) {
    if (p.pid != me)
      continue; // ignore contexts owned by other processes
    found = true;
    if (p.num_cols != cols)
      throw std::runtime_error("full partition (ctx " + p.metadata.id + ") reports num_col " +
        std::to_string(p.num_cols) + ", expected " + std::to_string(cols));
    if (p.start_col != 0)
      throw std::runtime_error("full partition (ctx " + p.metadata.id + ") reports start_col " +
        std::to_string(p.start_col) + ", expected 0");
  }
  if (!found)
    throw std::runtime_error("no partition reported for this process");

  std::cout << "  full-array partition created at start_col 0, num_col == "
            << cols << std::endl;
}

//
// A full-array partition pinned at a non-zero start column cannot fit and is
// rejected.
//
void
TEST_partition_full_at_nonzero_col(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  auto dev = sdev.get();
  auto cols = total_columns(dev);
  if (cols == 0)
    throw std::runtime_error("device reports no columns");

  try {
    auto ctx = create_partition(dev, cols, NONZERO_START_COL);
  } catch (const std::exception& e) {
    std::cout << "  full-array create at start_col " << NONZERO_START_COL
              << " correctly rejected: " << e.what() << std::endl;
    return;
  }
  throw std::runtime_error("full-array create at start_col " +
    std::to_string(NONZERO_START_COL) + " succeeded");
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
  require_columns(dev, MIN_PLACED_COLS);

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
  require_columns(dev, MIN_PLACED_COLS);

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
  require_columns(dev, MIN_PLACED_COLS);

  auto p1 = create_partition(dev, 4, 4); // cols 4-7
  auto p2 = create_partition(dev, 4, 8); // cols 8-11

  std::cout << "  non-overlapping partitions (start 4 width 4, start 8 width 4) created"
            << std::endl;
}

//
// Probe whether a 6-column partition is accepted at all, independent of where
// it is placed: create a single one with no start column (flexible placement).
// Width 6 is not a multiple of the firmware's column alignment, so this
// isolates that rule from any start-column rules. The outcome is reported
// rather than asserted.
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

void
TEST_partition(device::id_type id, std::shared_ptr<device>& sdev, arg_type& arg)
{
  struct step {
    const char *name;
    void (*fn)(device::id_type, std::shared_ptr<device>&, arg_type&);
  };
  const step steps[] = {
    { "full-array pinned at start_col 0", TEST_partition_full_at_col0 },
    { "full-array pinned at non-zero start_col", TEST_partition_full_at_nonzero_col },
    { "overlapping partitions conflict", TEST_partition_overlap_conflict },
    { "identical partitions share", TEST_partition_identical_ok },
    { "non-overlapping partitions", TEST_partition_adjacent_ok },
    { "width-6 no start column", TEST_partition_width6_flexible },
    { "width-6 start column scan", TEST_partition_width6_start_scan },
  };

  std::vector<std::string> failed;
  for (const auto& s : steps) {
    std::cout << "-- " << s.name << std::endl;
    try {
      s.fn(id, sdev, arg);
    } catch (const std::exception& e) {
      std::cout << "  FAILED: " << e.what() << std::endl;
      failed.push_back(std::string(s.name) + ": " + e.what());
    }
  }

  if (failed.empty())
    return;

  std::string msg = std::to_string(failed.size()) + " partition check(s) failed:";
  for (const auto& f : failed)
    msg += "\n  " + f;
  throw std::runtime_error(msg);
}
