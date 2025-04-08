// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "io.h"
#include "hwctx.h"
#include "exec_buf.h"
#include "io_config.h"
#include "core/common/aiebu/src/cpp/aiebu/src/include/aiebu_assembler.h"

#include <string>
#include <regex>

using namespace xrt_core;

namespace {

const char *io_test_bo_type_names[] = {
  "IO_TEST_BO_CMD",
  "IO_TEST_BO_INSTRUCTION",
  "IO_TEST_BO_INPUT",
  "IO_TEST_BO_PARAMETERS",
  "IO_TEST_BO_OUTPUT",
  "IO_TEST_BO_INTERMEDIATE",
  "IO_TEST_BO_MC_CODE",
  "IO_TEST_BO_BAD_INSTRUCTION",
  "IO_TEST_BO_CTRL_PKT_PM",
  "IO_TEST_BO_SCRATCH_PAD",
};

void
alloc_bo(io_test_bo& ibo, device* dev, io_test_bo_type t)
{
  auto sz = ibo.size;

  if (sz == 0) {
    ibo.tbo = nullptr;
    return;
  }

  switch(t) {
  case IO_TEST_BO_CMD:
    ibo.tbo = std::make_shared<bo>(dev, sz, XCL_BO_FLAGS_EXECBUF);
    break;
  case IO_TEST_BO_INSTRUCTION:
    ibo.tbo = std::make_shared<bo>(dev, sz, XCL_BO_FLAGS_CACHEABLE);
    break;
  default:
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
  std::unique_ptr<aiebu::aiebu_assembler> asp = nullptr;

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
io_test_bo_set(device* dev, const std::string& xclbin_name) :
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
      alloc_bo(ibo, m_dev, type);
      init_bo(ibo, m_local_data_path + ifm_file);
      break;
    case IO_TEST_BO_PARAMETERS:
      ibo.size = PARAM_SIZE(tp);
      alloc_bo(ibo, m_dev, type);
      init_bo(ibo, m_local_data_path + param_file);
      break;
    case IO_TEST_BO_OUTPUT:
      ibo.size = OFM_SIZE(tp);
      alloc_bo(ibo, m_dev, type);
      break;
    case IO_TEST_BO_INTERMEDIATE:
      ibo.size = INTER_SIZE(tp);
      alloc_bo(ibo, m_dev, type);
      break;
    case IO_TEST_BO_MC_CODE:
      // Do not support patching MC_CODE. */
      if (MC_CODE_SIZE(tp))
        throw std::runtime_error("MC_CODE_SIZE is non zero!!!");
      ibo.size = DUMMY_MC_CODE_BUFFER_SIZE;
      alloc_bo(ibo, m_dev, type);
      break;
    case IO_TEST_BO_CTRL_PKT_PM:
    case IO_TEST_BO_SCRATCH_PAD:
      // No need for ctrl_pm and scratch pad BO
      break;
    default:
      throw std::runtime_error(std::string("unknown BO type ") + std::to_string(type));
      break;
    }
  }
}

io_test_bo_set::
io_test_bo_set(device* dev) : io_test_bo_set(dev, get_xclbin_name(dev))
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
  , m_type(get_kernel_type(dev, xclbin_name.c_str()))
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
      ibo.size = exec_buf::get_ctrl_code_size(m_elf);
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
    case IO_TEST_BO_SCRATCH_PAD:
      // Scratch pad buffer is required for preemption kernel
      if (m_type == KERNEL_TYPE_TXN_PREEMPT) {
        // Only support mem tile size for NPU4
        const size_t mem_tile_sz = 512 * 1024;
        ibo.size = mem_tile_sz * get_column_size(m_local_data_path + "/" + xclbin_name);
        alloc_bo(ibo, m_dev, type);
      }
      break;
    default:
      throw std::runtime_error("unknown BO type");
      break;
    }
  }
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
    case IO_TEST_BO_PARAMETERS:
    case IO_TEST_BO_MC_CODE:
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
  uint32_t cmd;

  switch (m_type) {
  case KERNEL_TYPE_TXN:
    cmd = ERT_START_NPU;
    break;
  case KERNEL_TYPE_TXN_PREEMPT:
    cmd = ERT_START_NPU_PREEMPT;
    break;
  default:
    throw std::runtime_error(std::string("Unknown kernel type: ") + std::to_string(m_type));
  }
  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), cmd);
  ebuf.set_cu_idx(idx);
  ebuf.add_ctrl_bo(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());
  ebuf.add_arg_64(3);
  ebuf.add_arg_64(0);
  ebuf.add_arg_32(0);
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INPUT].tbo.get());
  if (m_type == KERNEL_TYPE_TXN)
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_PARAMETERS].tbo.get());
  else
    ebuf.add_arg_64(0);
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_OUTPUT].tbo.get());
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  if (m_type == KERNEL_TYPE_TXN_PREEMPT) {
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_CTRL_PKT_PM].tbo.get(), "ctrlpkt-pm-0");
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_CTRL_PKT_PM].tbo.get(), "ctrlpkt-pm-1");
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_SCRATCH_PAD].tbo.get(), "scratch-pad-mem");
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_SCRATCH_PAD].tbo.get(), "scratch-pad-mem");
  }
  if (dump)
    ebuf.dump();

  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(), m_elf);
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
    p += io_test_bo_type_names[i] + std::to_string(getpid());
    dump_buf_to_file(ibo_p, ibo->size(), p);
    std::cout << "Dumping BO to: " << p << std::endl;
  }
}

void
io_test_bo_set::
verify_result()
{
  auto ofm_bo = m_bo_array[IO_TEST_BO_OUTPUT].tbo.get();
  auto ofm_p = reinterpret_cast<int8_t *>(ofm_bo->map());

  if (verify_output(ofm_p, m_local_data_path))
    throw std::runtime_error("Test failed!!!");
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

const char *
io_test_bo_set_base::
bo_type2name(int type)
{
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
