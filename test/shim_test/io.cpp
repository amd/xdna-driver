// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "io.h"
#include "hwctx.h"
#include "exec_buf.h"
#include "io_config.h"
#include "core/common/aiebu/src/cpp/include/aiebu/aiebu_assembler.h"

#include <climits>
#include <string>
#include <regex>

using namespace xrt_core;

namespace {

std::unique_ptr<aiebu::aiebu_assembler> asp = nullptr;

std::array io_test_bo_type_names {
  "IO_TEST_BO_CMD",
  "IO_TEST_BO_INSTRUCTION",
  "IO_TEST_BO_INPUT",
  "IO_TEST_BO_PARAMETERS",
  "IO_TEST_BO_OUTPUT",
  "IO_TEST_BO_INTERMEDIATE",
  "IO_TEST_BO_MC_CODE",
  "IO_TEST_BO_CTRL_PKT_PM",
  "IO_TEST_BO_SCRATCH_PAD",
  "IO_TEST_BO_SAVE_INSTRUCTION",
  "IO_TEST_BO_RESTORE_INSTRUCTION",
};

char *
aligned(const char *ptr, uintptr_t align)
{
  uintptr_t p = reinterpret_cast<uintptr_t>(ptr);
  uintptr_t aligned = (p + align - 1) & ~(align - 1);
  return reinterpret_cast<char *>(aligned);
}

void
alloc_bo(io_test_bo& ibo, device* dev, io_test_bo_type t, bool is_ubuf = false)
{
  auto sz = ibo.size;
  if (sz == 0) {
    ibo.tbo = nullptr;
    return;
  }

  static long page_size = 0;
  if (!page_size)
    page_size = sysconf(_SC_PAGESIZE);

  // Allocate large enough buffer to pass page algned user pointer for
  // BO creation. Buffer is initially filled based on type.
  if (is_ubuf)
    ibo.ubuf = std::vector<char>(sz + page_size - 1, t);

  switch(t) {
  case IO_TEST_BO_CMD:
    ibo.tbo = std::make_shared<bo>(dev, sz, XCL_BO_FLAGS_EXECBUF);
    break;
  case IO_TEST_BO_INSTRUCTION:
  case IO_TEST_BO_SAVE_INSTRUCTION:
  case IO_TEST_BO_RESTORE_INSTRUCTION:
    ibo.tbo = std::make_shared<bo>(dev, sz, XCL_BO_FLAGS_CACHEABLE);
    break;
  default:
    if (ibo.ubuf.size())
      ibo.tbo = std::make_shared<bo>(dev, aligned(ibo.ubuf.data(), page_size), sz);
    else
      ibo.tbo = std::make_shared<bo>(dev, sz);
    break;
  }
}

void
init_bo(io_test_bo& ibo, const std::string& bin)
{
  read_data_from_bin(bin, ibo.init_offset, ibo.tbo->size() - ibo.init_offset, ibo.tbo->map());
}

size_t
get_bin_size(const std::string& filename)
{
  std::ifstream ifs(filename, std::ifstream::ate | std::ifstream::binary);
  if (!ifs.is_open())
    return 0;
  return ifs.tellg();
}

std::tuple<uint32_t, uint32_t, uint32_t>
get_ofm_format(const std::string& config_file)
{
    std::ifstream config(config_file);
    if (!config)
      return { 0, 0, 0 };

    std::map<std::string, uint32_t> conf;
    std::string line;
    while (std::getline(config, line)) {
        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value))
            conf[key] = std::stoul(value);
    }
    return { conf["valid_bytes_per_section"], conf["section_size"], conf["total_size"] };
}

xrt::elf
txn2elf(std::vector<char>& txn_buf, std::vector<char>& pm_ctrlpkt)
{
  if (pm_ctrlpkt.size()) {
    std::vector<char> buffer2 = {};
    std::vector<char> patch_json = {};
    std::vector<std::string> libs = { "preempt" };
    std::vector<std::string> libpaths = { get_preemption_libs_path() };
    std::map< uint32_t, std::vector<char> > m_ctrlpkt = {};
    m_ctrlpkt[0] = pm_ctrlpkt;
    m_ctrlpkt[1] = pm_ctrlpkt;
    asp = std::make_unique<aiebu::aiebu_assembler>(
      aiebu::aiebu_assembler::buffer_type::blob_instr_transaction, txn_buf,
      buffer2, patch_json, libs, libpaths, m_ctrlpkt);
  } else {
    asp = std::make_unique<aiebu::aiebu_assembler>(
      aiebu::aiebu_assembler::buffer_type::blob_instr_transaction, txn_buf);
  }
  auto elf_buf = asp->get_elf();
  std::istringstream elf_stream;
  elf_stream.rdbuf()->pubsetbuf(elf_buf.data(), elf_buf.size());
  //dump_buf_to_file((int8_t*)elf_buf.data(), elf_buf.size(), "/tmp/elf");
  xrt::elf elf{elf_stream};
  return elf;
}

const xrt::elf
txn_file2elf(const std::string& ml_txn, const std::string& pm_ctrlpkt)
{
  size_t instr_size = get_bin_size(ml_txn);
  if (instr_size == 0)
    throw std::runtime_error("Zero instruction length");
  std::vector<char> txn_buf(instr_size);
  read_data_from_bin(ml_txn, 0, instr_size, reinterpret_cast<int*>(txn_buf.data()));

  size_t pm_ctrlpkt_size = get_bin_size(pm_ctrlpkt);
  std::vector<char> pm_ctrlpkt_buf(pm_ctrlpkt_size);
  if (pm_ctrlpkt_size)
    read_data_from_bin(pm_ctrlpkt, 0, pm_ctrlpkt_size, reinterpret_cast<int*>(pm_ctrlpkt_buf.data()));
  return txn2elf(txn_buf, pm_ctrlpkt_buf);
}

unsigned long
get_fine_preemption_checkpoints(const xrt::elf elf)
{
  unsigned long count = 0;
  std::ostringstream out;
  size_t pos = 0;

  asp->get_report(out);
  std::string report = out.str();

  // Find occurrences of XAIE_IO_PREEMPT in the string
  while ((pos = report.find("XAIE_IO_PREEMPT", pos)) != std::string::npos) {
      pos += std::string("XAIE_IO_PREEMPT").length();
      std::istringstream stream(report.substr(pos));
      unsigned long value;

      // Validate the extraction
      if (!(stream >> value)) {
          std::cerr << "Unable to parse preemption value at position " << pos << "\n";
          continue;
      }

      if (count > ULONG_MAX - value)
          throw std::overflow_error("Overflow detected while calculating preemption checkpoints");

      count += value;
  }

  if (!count)
    throw std::runtime_error("Preemptible kernel must have atleast 1 preemption checkpoint");

  return count;
}

std::vector<std::pair<int, uint64_t>>
get_fine_preemption_counters(device *dev)
{
  std::vector<std::pair<int, uint64_t>> counters;

  const auto telemetry = device_query<query::rtos_telemetry>(dev);
  for (auto& task : telemetry) {
    auto user_tid = task.preemption_data.slot_index;
    auto value = task.preemption_data.preemption_checkpoint_event;

    counters.emplace_back(user_tid, value);
  }
  return counters;
}

int
force_fine_preemption(device *dev, bool control)
{
  try {
    device_update<query::preemption>(dev, static_cast<uint32_t>(control));
  }
  catch (const std::runtime_error& e) {
    if (errno == EACCES) {
      std::cerr << "User doesn't have admin privilege. Skipping force preemption.\n";
      return -1;
    }
  }
  catch (...) {
    throw std::runtime_error("Caught an unknown exception.");
  }

  return 0;
}

} // namespace

io_test_bo_set_base::
io_test_bo_set_base(device* dev, const std::string& xclbin_name) :
  m_bo_array{}
  , m_xclbin_name(xclbin_name)
  , m_local_data_path(get_xclbin_data(dev, xclbin_name.c_str()))
  , m_dev(dev)
{
}

io_test_bo_set::
io_test_bo_set(device* dev, const std::string& xclbin_name, bool use_ubuf) :
  io_test_bo_set_base(dev, xclbin_name)
{
  std::string file;
  auto tp = parse_config_file(m_local_data_path + config_file);

  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);

    switch(type) {
    case IO_TEST_BO_CMD:
      ibo.size = 0x1000;
      alloc_bo(ibo, m_dev, type);
      break;
    case IO_TEST_BO_INSTRUCTION:
      file = m_local_data_path + instr_file;
      ibo.size = get_instr_size(file) * sizeof(int32_t);
      if (ibo.size == 0)
        throw std::runtime_error("instruction size cannot be 0");
      alloc_bo(ibo, m_dev, type);
      read_instructions_from_txt(file, ibo.tbo->map());
      break;
    case IO_TEST_BO_INPUT:
      ibo.size = IFM_SIZE(tp);
      ibo.init_offset = IFM_DIRTY_BYTES(tp);
      alloc_bo(ibo, m_dev, type, use_ubuf);
      init_bo(ibo, m_local_data_path + ifm_file);
      break;
    case IO_TEST_BO_PARAMETERS:
      ibo.size = PARAM_SIZE(tp);
      alloc_bo(ibo, m_dev, type, use_ubuf);
      init_bo(ibo, m_local_data_path + param_file);
      break;
    case IO_TEST_BO_OUTPUT:
      ibo.size = OFM_SIZE(tp);
      alloc_bo(ibo, m_dev, type, use_ubuf);
      break;
    case IO_TEST_BO_INTERMEDIATE:
      ibo.size = INTER_SIZE(tp);
      alloc_bo(ibo, m_dev, type, use_ubuf);
      break;
    case IO_TEST_BO_MC_CODE:
      // Do not support patching MC_CODE. */
      if (MC_CODE_SIZE(tp))
        throw std::runtime_error("MC_CODE_SIZE is non zero!!!");
      ibo.size = DUMMY_MC_CODE_BUFFER_SIZE;
      alloc_bo(ibo, m_dev, type, use_ubuf);
      break;
    case IO_TEST_BO_CTRL_PKT_PM:
    case IO_TEST_BO_SCRATCH_PAD:
    case IO_TEST_BO_SAVE_INSTRUCTION:
    case IO_TEST_BO_RESTORE_INSTRUCTION:
      // No need for ctrl_pm, scratch pad, save and restore instruction BOs
      // They are meant for ELF flow.
      break;
    default:
      throw std::runtime_error(std::string("unknown BO type ") + std::to_string(type));
      break;
    }
  }
}

io_test_bo_set::
io_test_bo_set(device* dev) : io_test_bo_set(dev, get_xclbin_name(dev), false)
{
}

io_test_bo_set::
io_test_bo_set(device* dev, bool use_ubuf) : io_test_bo_set(dev, get_xclbin_name(dev), use_ubuf)
{
}

uint32_t
get_column_size(const std::string& xclbin_path)
{
  auto xclbin = xrt::xclbin(xclbin_path);
  auto axlf = xclbin.get_axlf();
  auto aie_partition = xrt_core::xclbin::get_aie_partition(axlf);
  return aie_partition.ncol;
}

elf_io_test_bo_set::
elf_io_test_bo_set(device* dev, const std::string& xclbin_name) :
  io_test_bo_set_base(dev, xclbin_name)
  , m_elf(txn_file2elf(m_local_data_path + "/ml_txn.bin", m_local_data_path + "/pm_ctrlpkt.bin"))
{
  std::string file;

  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);

    switch(type) {
    case IO_TEST_BO_CMD:
      ibo.size = 0x1000;
      alloc_bo(ibo, m_dev, type);
      break;
    case IO_TEST_BO_INSTRUCTION:
      ibo.size = exec_buf::get_ctrl_code_size(m_elf, xrt_core::patcher::buf_type::ctrltext);
      if (ibo.size == 0)
        throw std::runtime_error("instruction size cannot be 0");
      alloc_bo(ibo, m_dev, type);
      break;
    case IO_TEST_BO_INPUT:
      file = m_local_data_path + "/ifm.bin";
      ibo.size = get_bin_size(file);
      alloc_bo(ibo, m_dev, type);
      init_bo(ibo, file);
      break;
    case IO_TEST_BO_PARAMETERS:
      file = m_local_data_path + "/wts.bin";
      ibo.size = get_bin_size(file);
      // May not have wts.bin
      if (ibo.size) {
        alloc_bo(ibo, m_dev, type);
        init_bo(ibo, file);
      }
      break;
    case IO_TEST_BO_OUTPUT:
      file = m_local_data_path + "/ofm.bin";
      ibo.size = get_bin_size(file);
      alloc_bo(ibo, m_dev, type);
      break;
    case IO_TEST_BO_INTERMEDIATE:
    case IO_TEST_BO_MC_CODE:
      // No need for intermediate/mc_code BO
      break;
    case IO_TEST_BO_CTRL_PKT_PM:
      file = m_local_data_path + "/pm_ctrlpkt.bin";
      ibo.size = get_bin_size(file);
      // May not have pm_ctrlpkt.bin
      if (ibo.size) {
        alloc_bo(ibo, m_dev, type);
        init_bo(ibo, file);
      }
      break;
    case IO_TEST_BO_SAVE_INSTRUCTION:
    case IO_TEST_BO_RESTORE_INSTRUCTION:
    case IO_TEST_BO_SCRATCH_PAD:
      // Save, restore instruction and scratch pad buffer is required for preemption kernel
      break;
    default:
      throw std::runtime_error("unknown BO type");
      break;
    }
  }
}

elf_preempt_io_test_bo_set::
elf_preempt_io_test_bo_set(device* dev, const std::string& xclbin_name) :
  io_test_bo_set_base(dev, xclbin_name)
  , m_elf(txn_file2elf(m_local_data_path + "/ml_txn.bin", m_local_data_path + "/pm_ctrlpkt.bin"))
  , m_total_fine_preemption_checkpoints(get_fine_preemption_checkpoints(m_elf))
{
  std::string file;

  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);

    switch(type) {
    case IO_TEST_BO_CMD:
      ibo.size = 0x1000;
      alloc_bo(ibo, m_dev, type);
      break;
    case IO_TEST_BO_INSTRUCTION:
      ibo.size = exec_buf::get_ctrl_code_size(m_elf, xrt_core::patcher::buf_type::ctrltext);
      if (ibo.size == 0)
        throw std::runtime_error("instruction size cannot be 0");
      alloc_bo(ibo, m_dev, type);
      break;
    case IO_TEST_BO_SAVE_INSTRUCTION:
      ibo.size = exec_buf::get_ctrl_code_size(m_elf, xrt_core::patcher::buf_type::preempt_save);
      if (ibo.size == 0)
        throw std::runtime_error("save instruction size cannot be 0");
      alloc_bo(ibo, m_dev, type);
      break;
    case IO_TEST_BO_RESTORE_INSTRUCTION:
      ibo.size = exec_buf::get_ctrl_code_size(m_elf, xrt_core::patcher::buf_type::preempt_restore);
      if (ibo.size == 0)
        throw std::runtime_error("restore instruction size cannot be 0");
      alloc_bo(ibo, m_dev, type);
      break;
    case IO_TEST_BO_INPUT:
      file = m_local_data_path + "/ifm.bin";
      ibo.size = get_bin_size(file);
      alloc_bo(ibo, m_dev, type);
      init_bo(ibo, file);
      break;
    case IO_TEST_BO_PARAMETERS:
      file = m_local_data_path + "/wts.bin";
      ibo.size = get_bin_size(file);
      // May not have wts.bin
      if (ibo.size) {
        alloc_bo(ibo, m_dev, type);
        init_bo(ibo, file);
      }
      break;
    case IO_TEST_BO_OUTPUT:
      file = m_local_data_path + "/ofm.bin";
      ibo.size = get_bin_size(file);
      alloc_bo(ibo, m_dev, type);
      break;
    case IO_TEST_BO_INTERMEDIATE:
    case IO_TEST_BO_MC_CODE:
      // No need for intermediate/mc_code BO
      break;
    case IO_TEST_BO_CTRL_PKT_PM:
      file = m_local_data_path + "/pm_ctrlpkt.bin";
      ibo.size = get_bin_size(file);
      // May not have pm_ctrlpkt.bin
      if (ibo.size) {
        alloc_bo(ibo, m_dev, type);
        init_bo(ibo, file);
      }
      break;
    case IO_TEST_BO_SCRATCH_PAD: {
      // Only support mem tile size for NPU4
      const size_t mem_tile_sz = 512 * 1024;

      ibo.size = mem_tile_sz * get_column_size(m_local_data_path + "/" + xclbin_name);
      alloc_bo(ibo, m_dev, type);
      break;
    }
    default:
      throw std::runtime_error("Unknown BO type");
    }
  }
  ++m_total_cmds;
}

void
io_test_bo_set_base::
sync_before_run()
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    io_test_bo *ibo = &m_bo_array[i];

    if (ibo->tbo == nullptr)
      continue;

    switch(i) {
    case IO_TEST_BO_INPUT:
    case IO_TEST_BO_INSTRUCTION:
    case IO_TEST_BO_SAVE_INSTRUCTION:
    case IO_TEST_BO_RESTORE_INSTRUCTION:
    case IO_TEST_BO_PARAMETERS:
    case IO_TEST_BO_MC_CODE:
    case IO_TEST_BO_CTRL_PKT_PM:
    case IO_TEST_BO_SCRATCH_PAD:
      ibo->tbo->get()->sync(buffer_handle::direction::host2device, ibo->tbo->size(), 0);
      break;
    default:
      break;
    }
  }
}

void
io_test_bo_set_base::
sync_after_run()
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    io_test_bo *ibo = &m_bo_array[i];

    if (ibo->tbo == nullptr)
      continue;

    switch(i) {
    case IO_TEST_BO_OUTPUT:
    case IO_TEST_BO_INTERMEDIATE:
      ibo->tbo->get()->sync(buffer_handle::direction::device2host, ibo->tbo->size(), 0);
      break;
    default:
      break;
    }
  }
}

void
io_test_bo_set::
init_cmd(xrt_core::cuidx_type idx, bool dump)
{
  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), ERT_START_CU);

  ebuf.set_cu_idx(idx);
  ebuf.add_arg_64(1);
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INPUT].tbo.get());
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_PARAMETERS].tbo.get());
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_OUTPUT].tbo.get());
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INTERMEDIATE].tbo.get());
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());
  ebuf.add_arg_32(m_bo_array[IO_TEST_BO_INSTRUCTION].tbo->size() / sizeof(int32_t));
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_MC_CODE].tbo.get());
  if (dump)
    ebuf.dump();
}

void
elf_io_test_bo_set::
init_cmd(xrt_core::cuidx_type idx, bool dump)
{
  auto dev_id = device_query<query::pcie_device>(m_dev);
  uint32_t cmd = ERT_START_NPU;

  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), cmd);
  ebuf.set_cu_idx(idx);
  ebuf.add_ctrl_bo(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());
  ebuf.add_arg_64(3);
  ebuf.add_arg_64(0);
  ebuf.add_arg_32(0);
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INPUT].tbo.get());
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_PARAMETERS].tbo.get());
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_OUTPUT].tbo.get());
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  if (dump)
    ebuf.dump();

  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(),
    xrt_core::patcher::buf_type::ctrltext, m_elf);
}

void
elf_preempt_io_test_bo_set::
init_cmd(xrt_core::cuidx_type idx, bool dump)
{
  auto dev_id = device_query<query::pcie_device>(m_dev);
  uint32_t cmd = ERT_START_NPU_PREEMPT;

  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), cmd);
  ebuf.set_cu_idx(idx);
  ebuf.add_ctrl_bo(
    *m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(),
    *m_bo_array[IO_TEST_BO_SAVE_INSTRUCTION].tbo.get(),
    *m_bo_array[IO_TEST_BO_RESTORE_INSTRUCTION].tbo.get()
  );
  ebuf.add_arg_64(3);
  ebuf.add_arg_64(0);
  ebuf.add_arg_32(0);
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INPUT].tbo.get());
  ebuf.add_arg_64(0);
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_OUTPUT].tbo.get());
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_CTRL_PKT_PM].tbo.get(), "ctrlpkt-pm-0");
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_CTRL_PKT_PM].tbo.get(), "ctrlpkt-pm-1");
  ebuf.add_scratchpad_bo(*m_bo_array[IO_TEST_BO_SCRATCH_PAD].tbo.get());
  if (dump)
    ebuf.dump();

  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(),
    xrt_core::patcher::buf_type::ctrltext, m_elf);
  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_SAVE_INSTRUCTION].tbo.get(),
    xrt_core::patcher::buf_type::preempt_save, m_elf);
  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_RESTORE_INSTRUCTION].tbo.get(),
    xrt_core::patcher::buf_type::preempt_restore, m_elf);

  if (force_fine_preemption(m_dev, true))
    return;

  const auto info = device_query<query::aie_partition_info>(m_dev);
  auto pid = getpid();

  for (auto& partition: info) {
    if (partition.pid == pid)
      m_user_tid = std::stoi(partition.metadata.id);
  }

  if (m_user_tid == -1)
    throw std::runtime_error("Invalid user task ID!");

  m_fine_preemptions = get_fine_preemption_counters(m_dev);
}

// For debug only
void
io_test_bo_set_base::
dump_content()
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto ibo = m_bo_array[i].tbo.get();

    if (ibo == nullptr)
      continue;

    auto ibo_p = reinterpret_cast<int8_t *>(ibo->map());
    std::string p("/tmp/");
    p += bo_type2name(i) + std::to_string(getpid());
    dump_buf_to_file(ibo_p, ibo->size(), p);
    printf("Dumped BO (va: %p, xdna: %ld) to %s\n", ibo_p, ibo->paddr(), p.c_str());
  }
}

void
io_test_bo_set::
verify_result()
{
  auto ofm_bo = m_bo_array[IO_TEST_BO_OUTPUT].tbo.get();
  auto ofm_p = reinterpret_cast<int8_t *>(ofm_bo->map());

  if (verify_output(ofm_p, m_local_data_path)) {
    dump_content();
    throw std::runtime_error("Test failed!!!");
  }
}

void
elf_io_test_bo_set::
verify_result()
{
  auto bo_ofm = m_bo_array[IO_TEST_BO_OUTPUT].tbo;
  auto ofm_p = reinterpret_cast<char*>(bo_ofm->map());
  auto sz = bo_ofm->size();

  std::vector<char> buf_ofm_golden(sz);
  auto ofm_golden_p = reinterpret_cast<char*>(buf_ofm_golden.data());
  read_data_from_bin(m_local_data_path + "/ofm.bin", 0, sz, reinterpret_cast<int*>(ofm_golden_p));

  auto [ valid_per_sec, sec_size, total_size ] = get_ofm_format(m_local_data_path + "/ofm_format.ini");
  if (total_size == 0)
    valid_per_sec = sec_size = total_size = sz;
  size_t count = 0;
  for (size_t i = 0; i < total_size; i += sec_size) {
    for (size_t j = i; j < i + valid_per_sec; j++) {
      if (ofm_p[i] != ofm_golden_p[i])
        count++;
    }
  }
  if (count)
    throw std::runtime_error(std::to_string(count) + " bytes result mismatch!!!");
}

void
elf_preempt_io_test_bo_set::
verify_result()
{
  auto bo_ofm = m_bo_array[IO_TEST_BO_OUTPUT].tbo;
  auto ofm_p = reinterpret_cast<char*>(bo_ofm->map());
  auto sz = bo_ofm->size();

  std::vector<char> buf_ofm_golden(sz);
  auto ofm_golden_p = reinterpret_cast<char*>(buf_ofm_golden.data());
  read_data_from_bin(m_local_data_path + "/ofm.bin", 0, sz, reinterpret_cast<int*>(ofm_golden_p));

  auto [ valid_per_sec, sec_size, total_size ] = get_ofm_format(m_local_data_path + "/ofm_format.ini");
  if (total_size == 0)
    valid_per_sec = sec_size = total_size = sz;
  size_t count = 0;
  for (size_t i = 0; i < total_size; i += sec_size) {
    for (size_t j = i; j < i + valid_per_sec; j++) {
      if (ofm_p[i] != ofm_golden_p[i])
        count++;
    }
  }
  if (count)
    throw std::runtime_error(std::to_string(count) + " bytes result mismatch!!!");

  if (force_fine_preemption(m_dev, false))
    return;

  std::vector<std::pair<int, uint64_t>> post_run = get_fine_preemption_counters(m_dev);
  uint64_t fine_preemption_count;
  int hw_ctx_id = -1;

  // Find the HW Context ID for the current user TID
  for (auto i =  0; i < post_run.size(); i++) {
    auto tid = post_run[i].first;

    if (tid == m_user_tid) {
      fine_preemption_count = post_run[i].second;
      hw_ctx_id = i;
      break;
    }
  }

  if (hw_ctx_id == -1)
    throw std::runtime_error("Invalid hw context ID");

  auto delta = fine_preemption_count - m_fine_preemptions.at(hw_ctx_id).second;
  if (m_total_fine_preemption_checkpoints * m_total_cmds != delta)
    throw std::runtime_error("All cmds failed to preempt!");
}

const char *
io_test_bo_set_base::
bo_type2name(int type)
{
  if (IO_TEST_BO_MAX_TYPES > io_test_bo_type_names.size())
    throw std::runtime_error("Missing BO type names in io_test_bo_type_names[]");
  return io_test_bo_type_names[type];
}

void
io_test_bo_set_base::
run(const std::vector<xrt_core::fence_handle*>& wait_fences,
  const std::vector<xrt_core::fence_handle*>& signal_fences, bool no_check_result)
{
  hw_ctx hwctx{m_dev, m_xclbin_name.c_str()};
  auto hwq = hwctx.get()->get_hw_queue();
  auto kernel = get_kernel_name(m_dev, m_xclbin_name.c_str());
  if (kernel.empty())
    throw std::runtime_error("No kernel found");
  auto cu_idx = hwctx.get()->open_cu_context(kernel);
  std::cout << "Found kernel: " << kernel << " with cu index " << cu_idx.index << std::endl;

  init_cmd(cu_idx, false);
  sync_before_run();

  auto cbo = m_bo_array[IO_TEST_BO_CMD].tbo.get();
  auto chdl = cbo->get();
  for (const auto& fence : wait_fences)
    hwq->submit_wait(fence);
  hwq->submit_command(chdl);
  for (const auto& fence : signal_fences)
    hwq->submit_signal(fence);
  hwq->wait_command(chdl, 5000);
  auto cpkt = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());
  if (cpkt->state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("Command failed, state=") + std::to_string(cpkt->state));

  sync_after_run();
  if (!no_check_result)
    verify_result();
}

void
io_test_bo_set_base::
run()
{
  const std::vector<xrt_core::fence_handle*> sfences{};
  const std::vector<xrt_core::fence_handle*> wfences{};
  run(wfences, sfences, false);
}

void
io_test_bo_set_base::
run_no_check_result()
{
  const std::vector<xrt_core::fence_handle*> sfences{};
  const std::vector<xrt_core::fence_handle*> wfences{};
  run(wfences, sfences, true);
}

std::array<io_test_bo, IO_TEST_BO_MAX_TYPES>&
io_test_bo_set_base::
get_bos()
{
  return m_bo_array;
}
