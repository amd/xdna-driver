// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2026, Advanced Micro Devices, Inc. All rights reserved.

#include "io.h"
#include "io_config.h"
#include "core/common/aiebu/src/cpp/include/aiebu/aiebu_assembler.h"
#include "xrt/detail/xrt_error_code.h"

#include <climits>
#include <string>
#include <sstream>
#include <regex>

using namespace xrt_core;

namespace {

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
  "IO_TEST_BO_2ND_PARAMETERS",
  "IO_TEST_BO_PDI",
};

char *
aligned(const char *ptr, uintptr_t align)
{
  uintptr_t p = reinterpret_cast<uintptr_t>(ptr);
  uintptr_t aligned = (p + align - 1) & ~(align - 1);
  return reinterpret_cast<char *>(aligned);
}

void
alloc_cmd_bo(io_test_bo& ibo, device* dev)
{
  ibo.tbo = std::make_shared<bo>(dev, 0x1000l, XCL_BO_FLAGS_EXECBUF);
}

void
alloc_ctrl_bo(io_test_bo& ibo, device* dev, size_t size)
{
  ibo.tbo = std::make_shared<bo>(dev, size, XCL_BO_FLAGS_CACHEABLE);
}

void
alloc_data_bo(io_test_bo& ibo, device* dev, size_t size, bool is_ubuf)
{
  if (is_ubuf) {
    static long page_size = 0;
    if (!page_size)
      page_size = sysconf(_SC_PAGESIZE);

    // Allocate large enough buffer to pass page algned user pointer for
    // BO creation. Buffer is initially filled with 0xaa.
    ibo.ubuf = std::vector<char>(size + page_size - 1, 0xaa);
    ibo.tbo = std::make_shared<bo>(dev, aligned(ibo.ubuf.data(), page_size), size);
  } else {
    ibo.tbo = std::make_shared<bo>(dev, size);
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

std::tuple<size_t, std::vector<char>>
read_binary_file(const std::string& filename)
{
  size_t size = get_bin_size(filename);
  std::vector<char> bin_buf(size);

  if (size)
    read_data_from_bin(filename, 0, size, reinterpret_cast<int*>(bin_buf.data()));
  return { size, bin_buf };
}

const xrt::elf
txn_file2elf(const std::string& ml_txn, const std::string& pm_ctrlpkt)
{
  auto [ instr_size, txn_buf ] = read_binary_file(ml_txn);
  auto [ pm_ctrlpkt_size, pm_ctrlpkt_buf ] = read_binary_file(pm_ctrlpkt);

  if (!instr_size)
    throw std::runtime_error("Can't open TXN bin file: " + ml_txn);

  std::unique_ptr<aiebu::aiebu_assembler> asp = nullptr;
  if (pm_ctrlpkt_buf.size()) {
    std::vector<char> buffer2 = {};
    std::vector<char> patch_json = {};
    std::vector<std::string> libs = {};
    std::vector<std::string> libpaths = {};
    std::map< uint32_t, std::vector<char> > m_ctrlpkt = {};
    m_ctrlpkt[0] = pm_ctrlpkt_buf;
    m_ctrlpkt[1] = pm_ctrlpkt_buf;
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

unsigned long
get_fine_preemption_checkpoints(const std::string& ml_txn)
{
  unsigned long count = 0;
  std::ostringstream out;
  size_t pos = 0;

  auto [ instr_size, txn_buf ] = read_binary_file(ml_txn);
  if (!instr_size)
    throw std::runtime_error("Can't open TXN bin file?");

  auto asp = std::make_unique<aiebu::aiebu_assembler>(
    aiebu::aiebu_assembler::buffer_type::blob_instr_transaction, txn_buf);
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

uint32_t
get_column_size(const xrt::xclbin& xclbin)
{
  auto axlf = xclbin.get_axlf();
  auto aie_partition = xrt_core::xclbin::get_aie_partition(axlf);
  return aie_partition.ncol;
}

uint32_t
get_column_size(const xrt::elf& elf)
{
  return elf.get_partition_size();
}

void
elf_init_no_arg_cmd(xrt::elf& elf, cuidx_type idx, bool dump, bo& cmd, bo& inst)
{
  exec_buf ebuf(cmd, ERT_START_NPU);

  ebuf.set_cu_idx(idx);
  ebuf.add_arg_64(3);
  ebuf.add_arg_64(0);
  ebuf.add_arg_32(0);
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);

  if (dump)
    ebuf.dump();

  ebuf.add_ctrl_bo(inst);
  ebuf.patch_ctrl_code(inst, elf_patcher::buf_type::ctrltext, elf, elf_int::no_ctrl_code_id);
}

} // namespace

void
io_test_bo_set_base::
cache_cmd_header()
{
  auto cbo = m_bo_array[IO_TEST_BO_CMD].tbo.get();
  if (cbo)
    m_cached_header = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map())->header;
}

void
io_test_bo_set_base::
reset_cmd_header()
{
  auto cbo = m_bo_array[IO_TEST_BO_CMD].tbo.get();
  if (cbo && m_cached_header != 0) {
    auto cmd = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());
    cmd->header = m_cached_header;
  }
}

void
io_test_bo_set_base::
init_cmd(hw_ctx& hwctx, bool dump)
{
  cache_cmd_header();
}

io_test_bo_set_base::
io_test_bo_set_base(device* dev, const std::string& tag, const flow_type* flow) :
  m_bo_array{}
  , m_tag(tag)
  , m_local_data_path(get_binary_data(dev, tag.empty() ? nullptr : tag.c_str(), flow))
  , m_dev(dev)
  , m_flow(flow)
  , m_kernel_index(elf_int::no_ctrl_code_id)
{
}

void
io_test_bo_set_base::
create_data_bo_from_file(io_test_bo& ibo, const std::string filename, int flags)
{
  auto file = m_local_data_path + filename;
  auto size = get_bin_size(file);
  bool ubuf = !!(flags & m_FLAG_USR_BUF);
  bool dbuf = !!(flags & m_FLAG_DEV_BUF);
  bool opt = !!(flags & m_FLAG_OPT);
  bool nofill = !!(flags & m_FLAG_NO_FILL);

  if (size) {
    if (dbuf)
      alloc_ctrl_bo(ibo, m_dev, size);
    else
      alloc_data_bo(ibo, m_dev, size, ubuf);
    if (!nofill)
      init_bo(ibo, file);
  } else if (!opt) {
    std::string err = "Missing file: " + filename;
    throw std::runtime_error(err);
  }
}

void
io_test_bo_set_base::
create_ctrl_bo_from_elf(io_test_bo& ibo, xrt_core::elf_patcher::buf_type type)
{
  auto size = exec_buf::get_ctrl_code_size(m_elf, type, m_kernel_index);
  if (size == 0)
    throw std::runtime_error("instruction size cannot be 0");
  alloc_ctrl_bo(ibo, m_dev, size);
}

xrt_core::cuidx_type
io_test_bo_set_base::
get_cu_idx(hw_ctx& hwctx)
{
  auto kernel = get_kernel_name(m_dev, m_tag.empty() ? nullptr : m_tag.c_str(), m_flow);
  if (kernel.empty())
    throw std::runtime_error("No kernel found");
  auto cu_idx = hwctx.get()->open_cu_context(kernel);
  //std::cout << "Found kernel: " << kernel << " with cu index " << cu_idx.index << std::endl;
  return cu_idx;
}

io_test_bo_set::
io_test_bo_set(device* dev, const std::string& tag, bool use_ubuf, const flow_type* flow) :
  io_test_bo_set_base(dev, tag, flow)
{
  std::string file;
  auto tp = parse_config_file(m_local_data_path + config_file);

  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);
    size_t size;

    switch(type) {
    case IO_TEST_BO_CMD:
      alloc_cmd_bo(ibo, m_dev);
      break;
    case IO_TEST_BO_INSTRUCTION:
      file = m_local_data_path + instr_file;
      size = get_instr_size(file) * sizeof(int32_t);
      if (size == 0)
        throw std::runtime_error("instruction size cannot be 0");
      alloc_ctrl_bo(ibo, m_dev, size);
      read_instructions_from_txt(file, ibo.tbo->map());
      break;
    case IO_TEST_BO_INPUT:
      ibo.init_offset = IFM_DIRTY_BYTES(tp);
      alloc_data_bo(ibo, m_dev, IFM_SIZE(tp), use_ubuf);
      init_bo(ibo, m_local_data_path + ifm_file);
      break;
    case IO_TEST_BO_PARAMETERS:
      alloc_data_bo(ibo, m_dev, PARAM_SIZE(tp), use_ubuf);
      init_bo(ibo, m_local_data_path + param_file);
      break;
    case IO_TEST_BO_OUTPUT:
      alloc_data_bo(ibo, m_dev, OFM_SIZE(tp), use_ubuf);
      break;
    case IO_TEST_BO_INTERMEDIATE:
      alloc_data_bo(ibo, m_dev, OFM_SIZE(tp), use_ubuf);
      break;
    case IO_TEST_BO_MC_CODE:
      // Do not support patching MC_CODE. */
      if (MC_CODE_SIZE(tp))
        throw std::runtime_error("MC_CODE_SIZE is non zero!!!");
      alloc_data_bo(ibo, m_dev, DUMMY_MC_CODE_BUFFER_SIZE, use_ubuf);
      break;
    default:
      break;
    }
  }
}

io_test_bo_set::
io_test_bo_set(device* dev, const std::string& tag, const flow_type* flow) : io_test_bo_set(dev, tag, false, flow)
{
}

io_test_bo_set::
io_test_bo_set(device* dev, bool use_ubuf) : io_test_bo_set(dev, "", use_ubuf, nullptr)
{
}

elf_io_test_bo_set::
elf_io_test_bo_set(device* dev, const std::string& tag, const flow_type* flow) :
  io_test_bo_set_base(dev, tag, flow)
{
  // Find elf with the same name as xclbin file
  std::filesystem::path elf_path(get_binary_path(dev, tag.empty() ? nullptr : tag.c_str(), m_flow));
  elf_path.replace_extension(".elf");

  if (std::filesystem::exists(elf_path))
    m_elf = xrt::elf(elf_path);
  else
    m_elf = txn_file2elf(m_local_data_path + "ml_txn.bin", m_local_data_path + "pm_ctrlpkt.bin");

  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);
    size_t size;

    switch(type) {
    case IO_TEST_BO_CMD:
      alloc_cmd_bo(ibo, m_dev);
      break;
    case IO_TEST_BO_INSTRUCTION:
      create_ctrl_bo_from_elf(ibo, elf_patcher::buf_type::ctrltext);
      break;
    case IO_TEST_BO_INPUT:
      create_data_bo_from_file(ibo, "ifm.bin", m_FLAG_OPT);
      break;
    case IO_TEST_BO_PARAMETERS:
      create_data_bo_from_file(ibo, "wts.bin", m_FLAG_OPT);
      break;
    case IO_TEST_BO_OUTPUT:
      create_data_bo_from_file(ibo, "ofm.bin", m_FLAG_NO_FILL|m_FLAG_OPT);
      break;
    case IO_TEST_BO_CTRL_PKT_PM:
      create_data_bo_from_file(ibo, "pm_ctrlpkt.bin", m_FLAG_OPT);
      break;
    default:
      break;
    }
  }
}

elf_full_io_test_bo_set::
elf_full_io_test_bo_set(device* dev, const std::string& tag, const flow_type* flow)
  : io_test_bo_set_base(dev, tag, flow)
{
  auto elf_path = get_binary_path(dev, tag.empty() ? nullptr : tag.c_str(), m_flow);
  m_elf = xrt::elf(elf_path);
  auto mod = xrt::module{m_elf};
  auto kernel_name = get_kernel_name(dev, tag.empty() ? nullptr : tag.c_str(), m_flow);

  try {
    m_kernel_index = m_elf.get_handle()->get_ctrlcode_id(kernel_name);
  } catch (const std::exception&) {
    m_kernel_index = elf_int::no_ctrl_code_id;
  }

  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);

    switch(type) {
    case IO_TEST_BO_CMD:
      alloc_cmd_bo(ibo, m_dev);
      break;
    case IO_TEST_BO_INSTRUCTION:
      create_ctrl_bo_from_elf(ibo, elf_patcher::buf_type::ctrltext);
      break;
    case IO_TEST_BO_INPUT:
      create_data_bo_from_file(ibo, "ifm.bin", m_FLAG_OPT);
      break;
    case IO_TEST_BO_PARAMETERS:
      create_data_bo_from_file(ibo, "wts.bin", m_FLAG_OPT);
      break;
    case IO_TEST_BO_OUTPUT:
      create_data_bo_from_file(ibo, "ofm.bin", m_FLAG_NO_FILL|m_FLAG_OPT);
      break;
    default:
      break;
    }
  }
}

elf_preempt_io_test_bo_set::
elf_preempt_io_test_bo_set(device* dev, const std::string& tag, const flow_type* flow)
  : io_test_bo_set_base(dev, tag, flow)
  , m_is_full_elf(get_flow_type(dev, tag.empty() ? nullptr : tag.c_str(), m_flow) == PREEMPT_FULL_ELF)
  , m_total_fine_preemption_checkpoints(get_fine_preemption_checkpoints(m_local_data_path + "ml_txn.bin"))
{
  const char* tag_c = tag.empty() ? nullptr : tag.c_str();

  if (m_is_full_elf) {
    m_elf = xrt::elf(get_binary_path(dev, tag_c, m_flow));
    auto mod = xrt::module{m_elf};
    m_kernel_index = m_elf.get_handle()->get_ctrlcode_id(get_kernel_name(dev, tag_c, m_flow));
  } else {
    m_elf = txn_file2elf(m_local_data_path + "ml_txn.bin", m_local_data_path + "pm_ctrlpkt.bin");
    m_kernel_index = elf_int::no_ctrl_code_id;
  }

  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);
    size_t size;

    switch(type) {
    case IO_TEST_BO_CMD:
      alloc_cmd_bo(ibo, m_dev);
      break;
    case IO_TEST_BO_INSTRUCTION:
      create_ctrl_bo_from_elf(ibo, elf_patcher::buf_type::ctrltext);
      break;
    case IO_TEST_BO_SAVE_INSTRUCTION:
      create_ctrl_bo_from_elf(ibo, elf_patcher::buf_type::preempt_save);
      break;
    case IO_TEST_BO_RESTORE_INSTRUCTION:
      create_ctrl_bo_from_elf(ibo, elf_patcher::buf_type::preempt_restore);
      break;
    case IO_TEST_BO_INPUT:
      create_data_bo_from_file(ibo, "ifm.bin", 0);
      break;
    case IO_TEST_BO_PARAMETERS:
      create_data_bo_from_file(ibo, "wts.bin", m_FLAG_OPT);
      break;
    case IO_TEST_BO_2ND_PARAMETERS:
      create_data_bo_from_file(ibo, "wts_2nd.bin", m_FLAG_OPT);
      break;
    case IO_TEST_BO_OUTPUT:
      create_data_bo_from_file(ibo, "ofm.bin", m_FLAG_NO_FILL);
      break;
    case IO_TEST_BO_CTRL_PKT_PM:
      create_data_bo_from_file(ibo, "pm_ctrlpkt.bin", m_FLAG_OPT);
      break;
    case IO_TEST_BO_SCRATCH_PAD: {
      // Only support mem tile size for NPU4
      const size_t mem_tile_sz = 512 * 1024;

      if (get_flow_type(dev, tag_c, m_flow) == PREEMPT_FULL_ELF)
        size = mem_tile_sz * get_column_size(m_elf);
      else
        size = mem_tile_sz * get_column_size(xrt::xclbin(get_binary_path(dev, tag_c, m_flow)));
      alloc_data_bo(ibo, m_dev, size, false);
      break;
    }
    case IO_TEST_BO_PDI:
      create_data_bo_from_file(ibo, "pdi.bin", m_FLAG_OPT | m_FLAG_DEV_BUF);
      break;
    default:
      break;
    }
  }
}

elf_io_negative_test_bo_set::
elf_io_negative_test_bo_set(device* dev, const std::string& xclbin_name,
  const std::string& elf_name, uint32_t exp_status, uint32_t exp_txn_op_idx)
  : m_expect_txn_op_idx(exp_txn_op_idx)
  , m_expect_cmd_status(exp_status)
  , io_test_bo_set_base(dev, xclbin_name)
{
  m_elf = xrt::elf(m_local_data_path + elf_name);

  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);

    switch(type) {
    case IO_TEST_BO_CMD:
      alloc_cmd_bo(ibo, m_dev);
      break;
    case IO_TEST_BO_INSTRUCTION:
      create_ctrl_bo_from_elf(ibo, elf_patcher::buf_type::ctrltext);
      break;
    default:
      break;
    }
  }
}

elf_io_gemm_test_bo_set::
elf_io_gemm_test_bo_set(device* dev, const std::string& xclbin_name, const std::string& elf_name)
  : io_test_bo_set_base(dev, xclbin_name)
{
  m_elf = xrt::elf(m_local_data_path + elf_name);

  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);

    switch(type) {
    case IO_TEST_BO_CMD:
      alloc_cmd_bo(ibo, m_dev);
      break;
    case IO_TEST_BO_INSTRUCTION:
      create_ctrl_bo_from_elf(ibo, elf_patcher::buf_type::ctrltext);
      break;
    default:
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
    case IO_TEST_BO_SAVE_INSTRUCTION:
    case IO_TEST_BO_RESTORE_INSTRUCTION:
    case IO_TEST_BO_PARAMETERS:
    case IO_TEST_BO_MC_CODE:
    case IO_TEST_BO_CTRL_PKT_PM:
    case IO_TEST_BO_SCRATCH_PAD:
    case IO_TEST_BO_2ND_PARAMETERS:
    case IO_TEST_BO_PDI:
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
init_cmd(hw_ctx& hwctx, bool dump)
{
  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), ERT_START_CU);

  ebuf.set_cu_idx(get_cu_idx(hwctx));

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

  io_test_bo_set_base::init_cmd(hwctx, dump);
}

void
elf_io_test_bo_set::
init_cmd(hw_ctx& hwctx, bool dump)
{
  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), ERT_START_NPU);

  ebuf.set_cu_idx(get_cu_idx(hwctx));

  ebuf.add_arg_64(3);
  ebuf.add_arg_64(0);
  ebuf.add_arg_32(0);
  if (m_bo_array[IO_TEST_BO_INPUT].tbo.get()) {
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INPUT].tbo.get());
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_PARAMETERS].tbo.get());
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_OUTPUT].tbo.get());
  } else {
    ebuf.add_arg_64(0);
    ebuf.add_arg_64(0);
    ebuf.add_arg_64(0);
  }
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);

  if (dump)
    ebuf.dump();

  ebuf.add_ctrl_bo(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());
  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(),
    elf_patcher::buf_type::ctrltext, m_elf, elf_int::no_ctrl_code_id);

  io_test_bo_set_base::init_cmd(hwctx, dump);
}

void
elf_full_io_test_bo_set::
init_cmd(hw_ctx& hwctx, bool dump)
{
  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), ERT_START_DPU);

  xrt_core::cuidx_type cu_idx{0};
  ebuf.set_cu_idx(cu_idx);

  if (m_bo_array[IO_TEST_BO_INPUT].tbo.get()) {
    ebuf.add_arg_64(3);
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INPUT].tbo.get(), "0");
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_PARAMETERS].tbo.get(), "1");
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_OUTPUT].tbo.get(), "2");
  }

  if (dump)
    ebuf.dump();

  ebuf.add_ctrl_bo(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());
  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(),
    elf_patcher::buf_type::ctrltext, m_elf, m_kernel_index);

  io_test_bo_set_base::init_cmd(hwctx, dump);
}

void
elf_preempt_io_test_bo_set::
init_cmd(hw_ctx& hwctx, bool dump)
{
  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(),
    m_is_full_elf ? ERT_START_NPU_PREEMPT_ELF : ERT_START_NPU_PREEMPT);

  if (m_is_full_elf) {
    ebuf.add_arg_64(3);
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_PARAMETERS].tbo.get(), "0");
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_2ND_PARAMETERS].tbo.get(), "1");
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INPUT].tbo.get(), "2");
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_OUTPUT].tbo.get(), "3");
    ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_PDI].tbo.get(), ".pdi.0");
    ebuf.add_scratchpad_bo(*m_bo_array[IO_TEST_BO_SCRATCH_PAD].tbo.get());
  } else {
    ebuf.set_cu_idx(get_cu_idx(hwctx));

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
  }

  ebuf.add_ctrl_bo(
    *m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(),
    *m_bo_array[IO_TEST_BO_SAVE_INSTRUCTION].tbo.get(),
    *m_bo_array[IO_TEST_BO_RESTORE_INSTRUCTION].tbo.get()
  );

  if (dump)
    ebuf.dump();

  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(),
    elf_patcher::buf_type::ctrltext, m_elf, m_kernel_index);
  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_SAVE_INSTRUCTION].tbo.get(),
    elf_patcher::buf_type::preempt_save, m_elf, m_kernel_index);
  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_RESTORE_INSTRUCTION].tbo.get(),
    elf_patcher::buf_type::preempt_restore, m_elf, m_kernel_index);

  io_test_bo_set_base::init_cmd(hwctx, dump);
}

void
elf_io_negative_test_bo_set::
init_cmd(hw_ctx& hwctx, bool dump)
{
  elf_init_no_arg_cmd(m_elf, get_cu_idx(hwctx), dump,
    *m_bo_array[IO_TEST_BO_CMD].tbo.get(),
    *m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());

  io_test_bo_set_base::init_cmd(hwctx, dump);
}

void
elf_io_gemm_test_bo_set::
init_cmd(hw_ctx& hwctx, bool dump)
{
  elf_init_no_arg_cmd(m_elf, get_cu_idx(hwctx), dump,
    *m_bo_array[IO_TEST_BO_CMD].tbo.get(),
    *m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());

  // Get a debug BO
  auto boflags = XRT_BO_FLAGS_CACHEABLE;
  auto ext_boflags = XRT_BO_USE_DEBUG << 4;
  const size_t size = 4096;
  m_dbo = hwctx.get()->alloc_bo(size, get_bo_flags(boflags, ext_boflags));
  auto dbo_p = static_cast<int32_t *>(m_dbo->map(buffer_handle::map_type::write));

  // Initializing debug BO content to -1
  std::memset(dbo_p, 0xff, size);
  m_dbo.get()->sync(buffer_handle::direction::host2device, size, 0);

  io_test_bo_set_base::init_cmd(hwctx, dump);
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
io_test_bo_set_base::
verify_result()
{
  // Verify command completion status
  auto cbo = m_bo_array[IO_TEST_BO_CMD].tbo.get();
  auto cpkt = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());
  if (cpkt->state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("Command failed, state=") + std::to_string(cpkt->state));

  // If no ofm, skip the rest of validation
  auto bo_ofm = m_bo_array[IO_TEST_BO_OUTPUT].tbo;
  if (!bo_ofm)
    return;

  // Compare result with data in ofm.bin
  auto ofm_p = reinterpret_cast<char*>(bo_ofm->map());
  auto sz = bo_ofm->size();

  std::vector<char> buf_ofm_golden(sz);
  auto ofm_golden_p = reinterpret_cast<char*>(buf_ofm_golden.data());
  read_data_from_bin(m_local_data_path + "ofm.bin", 0, sz, reinterpret_cast<int*>(ofm_golden_p));

  auto [ valid_per_sec, sec_size, total_size ] = get_ofm_format(m_local_data_path + "ofm_format.ini");
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
io_test_bo_set::
verify_result()
{
  // Verify command completion status
  auto cbo = m_bo_array[IO_TEST_BO_CMD].tbo.get();
  auto cpkt = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());
  if (cpkt->state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("Command failed, state=") + std::to_string(cpkt->state));

  auto ofm_bo = m_bo_array[IO_TEST_BO_OUTPUT].tbo.get();
  auto ofm_p = reinterpret_cast<int8_t *>(ofm_bo->map());

  if (verify_output(ofm_p, m_local_data_path)) {
    dump_content();
    throw std::runtime_error("Test failed!!!");
  }
}

void
elf_io_negative_test_bo_set::
verify_result()
{
  auto cbo = m_bo_array[IO_TEST_BO_CMD].tbo.get();

  auto cpkt = reinterpret_cast<ert_packet *>(cbo->map());
  if (cpkt->state != m_expect_cmd_status) {
    throw std::runtime_error(std::string("Command status=") + std::to_string(cpkt->state) +
      ", expect=" + std::to_string(m_expect_cmd_status));
  }

  if (m_expect_cmd_status != ERT_CMD_STATE_TIMEOUT)
    return;

  // In case of timeout, further check context health data
  auto cdata = reinterpret_cast<ert_ctx_health_data_v1 *>(cpkt->data);
  if (cdata->aie2.txn_op_idx != m_expect_txn_op_idx) {
    std::cerr << "Incorrect app health data:\n";
    std::cerr << "\tTXN OP ID: 0x" << std::hex << cdata->aie2.txn_op_idx << "\n";
    std::cerr << "\tContext PC: 0x" << std::hex << cdata->aie2.ctx_pc << "\n";
    std::cerr << "\tFatal Error Type: 0x" << std::hex << cdata->aie2.fatal_error_type << "\n";
    std::cerr << "\tFatal error exception type: 0x" << std::hex << cdata->aie2.fatal_error_exception_type << "\n";
    std::cerr << "\tFatal error exception PC: 0x" << std::hex << cdata->aie2.fatal_error_exception_pc << "\n";
    std::cerr << "\tFatal error app module: 0x" << std::hex << cdata->aie2.fatal_error_app_module << "\n";
    throw std::runtime_error(std::string("TXN op index=") + std::to_string(cdata->aie2.txn_op_idx) +
      ", expect=" + std::to_string(m_expect_txn_op_idx));
  }
}

void
elf_io_gemm_test_bo_set::
verify_result()
{
  auto cbo = m_bo_array[IO_TEST_BO_CMD].tbo.get();
  auto cpkt = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());
  if (cpkt->state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("Command failed, state=") + std::to_string(cpkt->state));

  // Updating debug BO content after execution
  m_dbo.get()->sync(buffer_handle::direction::device2host, m_dbo->get_properties().size, 0);
  auto dbo_p = static_cast<int32_t *>(m_dbo->map(buffer_handle::map_type::write));

  // Validating debug BO content.
  // The first 32 Dwords should be 0xde, the rest should be initial values
  int i = 0;
  while (i < 32) {
    if (dbo_p[i] != 0xde)
      throw std::runtime_error(std::string("bad debug bo content, expecting 222, got ")
        + std::to_string(dbo_p[i]) + "@" + std::to_string(i));
    ++i;
  }
  while (i < 1024) {
    if (dbo_p[i] != -1)
      throw std::runtime_error(std::string("bad debug bo content, expecting -1, got ")
        + std::to_string(dbo_p[i]) + "@" + std::to_string(i));
    ++i;
  }
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
run(const std::vector<fence_handle*>& wait_fences,
  const std::vector<fence_handle*>& signal_fences, bool no_check_result)
{
  hw_ctx hwctx{m_dev, m_tag.empty() ? nullptr : m_tag.c_str(), m_flow};
  auto hwq = hwctx.get()->get_hw_queue();

  init_cmd(hwctx, false);
  sync_before_run();

  auto cbo = m_bo_array[IO_TEST_BO_CMD].tbo.get();
  reset_cmd_header();
  cache_cmd_header();

  for (const auto& fence : wait_fences)
    hwq->submit_wait(fence);
  hwq->submit_command(cbo->get());
  for (const auto& fence : signal_fences)
    hwq->submit_signal(fence);
  hwq->wait_command(cbo->get(), 0);

  sync_after_run();
  if (!no_check_result)
    verify_result();
}

void
io_test_bo_set_base::
run()
{
  const std::vector<fence_handle*> sfences{};
  const std::vector<fence_handle*> wfences{};
  run(wfences, sfences, false);
}

void
io_test_bo_set_base::
run_no_check_result()
{
  const std::vector<fence_handle*> sfences{};
  const std::vector<fence_handle*> wfences{};
  run(wfences, sfences, true);
}

std::array<io_test_bo, IO_TEST_BO_MAX_TYPES>&
io_test_bo_set_base::
get_bos()
{
  return m_bo_array;
}

unsigned long
io_test_bo_set_base::
get_preemption_checkpoints()
{
  return 0;
}

unsigned long
elf_preempt_io_test_bo_set::
get_preemption_checkpoints()
{
  return m_total_fine_preemption_checkpoints;
}

const std::map<uint32_t, enum xrtErrorNum>
async_error_io_test_bo_set::
m_shim_event_err_num_map = {
  {64, XRT_ERROR_NUM_AIE_BUS},
  {65, XRT_ERROR_NUM_AIE_STREAM},
  {66, XRT_ERROR_NUM_AIE_STREAM},
  {67, XRT_ERROR_NUM_AIE_BUS},
  {68, XRT_ERROR_NUM_AIE_BUS},
  {69, XRT_ERROR_NUM_AIE_BUS},
  {70, XRT_ERROR_NUM_AIE_BUS},
  {71, XRT_ERROR_NUM_AIE_BUS},
  {72, XRT_ERROR_NUM_AIE_DMA},
  {73, XRT_ERROR_NUM_AIE_DMA},
  {74, XRT_ERROR_NUM_AIE_LOCK},
};

async_error_io_test_bo_set::
async_error_io_test_bo_set(device* dev)
  : m_last_err_timestamp(0), io_test_bo_set_base(dev, "", nullptr)
{
  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);
    size_t size;

    switch(type) {
    case IO_TEST_BO_CMD:
      alloc_cmd_bo(ibo, m_dev);
      break;
    case IO_TEST_BO_INSTRUCTION: {
      auto size = 3 * sizeof(uint32_t);
      alloc_ctrl_bo(ibo, m_dev, size);

      auto instruction_p = ibo.tbo->map();
      // Error Event ID: 64
      // Expect "Row: 0, Col: 1, module 2, event ID 64, category 4" in dmesg
      uint32_t event_id = 0x00000040;
      instruction_p[0] = 0x02000000;
      instruction_p[1] = 0x00034008;
      instruction_p[2] = event_id;

      uint64_t err_num = m_shim_event_err_num_map.at(event_id);
      uint64_t err_drv = XRT_ERROR_DRIVER_AIE;
      uint64_t err_severity = XRT_ERROR_SEVERITY_CRITICAL;
      uint64_t err_module = XRT_ERROR_MODULE_AIE_PL;
      uint64_t err_class = XRT_ERROR_CLASS_AIE;
      m_expect_err_code = XRT_ERROR_CODE_BUILD(err_num, err_drv, err_severity, err_module, err_class);
      break;
    }
    default:
      break;
    }
  }
}

void
async_error_io_test_bo_set::
init_cmd(hw_ctx& hwctx, bool dump)
{
  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), ERT_START_CU);
  ebuf.set_cu_idx(get_cu_idx(hwctx));
  ebuf.add_arg_64(1);
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  ebuf.add_arg_64(0);
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());
  ebuf.add_arg_32(m_bo_array[IO_TEST_BO_INSTRUCTION].tbo->size() / sizeof(int32_t));

  if (dump)
    ebuf.dump();

  io_test_bo_set_base::init_cmd(hwctx, dump);
}

void
async_error_io_test_bo_set::
verify_result()
{
  // Don't care about command completion status, it may succeed or timeout

  auto buf = device_query<query::xocl_errors>(m_dev);
  if (buf.empty())
    throw std::runtime_error("failed to get async errors, return empty information.");

  auto ect = query::xocl_errors::to_value(buf, XRT_ERROR_CLASS_AIE);
  xrtErrorCode err_code;
  xrtErrorTime err_timestamp;
  std::tie(err_code, err_timestamp) = ect;
  if (err_code != m_expect_err_code) {
    std::stringstream ss;
    ss << "failed to get async errors, unexpected error code, 0x" << std::hex << err_code
       << ", 0x" << std::hex << m_expect_err_code << ".";
    throw std::runtime_error(ss.str());
  }
  if (err_timestamp == m_last_err_timestamp) {
    std::stringstream ss;
    ss << "failed to get async errors, return old timestamp: " << m_last_err_timestamp << ".";
    throw std::runtime_error(ss.str());
  }
  m_last_err_timestamp = err_timestamp;
}

async_error_aie4_io_test_bo_set::
async_error_aie4_io_test_bo_set(device* dev, const std::string& tag)
  : m_expect_err_code(0), m_last_err_timestamp(0), io_test_bo_set_base(dev, tag, nullptr)
{
  auto elf_path = get_binary_path(dev, tag.empty() ? nullptr : tag.c_str(), m_flow);
  m_elf = xrt::elf(elf_path);
  auto mod = xrt::module{m_elf};
  auto kernel_name = get_kernel_name(dev, tag.empty() ? nullptr : tag.c_str(), m_flow);

  try {
    m_kernel_index = m_elf.get_handle()->get_ctrlcode_id(kernel_name);
  } catch (const std::exception&) {
    m_kernel_index = elf_int::no_ctrl_code_id;
  }

  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);

    switch(type) {
    case IO_TEST_BO_CMD:
      alloc_cmd_bo(ibo, m_dev);
      break;
    case IO_TEST_BO_INSTRUCTION:
      create_ctrl_bo_from_elf(ibo, elf_patcher::buf_type::ctrltext);
      break;
    default:
      break;
    }
  }

  // bad_ctrl.elf triggers AIE4 context error (UC firmware exception)
  // error_type = UC_COMPLETION_TIMEOUT (4) or UC_CRITICAL_ERROR (5)
  // Both map to KDS_EXEC error number
  uint64_t err_num = XRT_ERROR_NUM_KDS_EXEC;
  uint64_t err_drv = XRT_ERROR_DRIVER_AIE;
  uint64_t err_severity = XRT_ERROR_SEVERITY_CRITICAL;
  uint64_t err_module = XRT_ERROR_MODULE_AIE_CORE;
  uint64_t err_class = XRT_ERROR_CLASS_AIE;
  m_expect_err_code = XRT_ERROR_CODE_BUILD(err_num, err_drv, err_severity, err_module, err_class);
}

void
async_error_aie4_io_test_bo_set::
init_cmd(hw_ctx& hwctx, bool dump)
{
  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), ERT_START_DPU);

  xrt_core::cuidx_type cu_idx{0};
  ebuf.set_cu_idx(cu_idx);

  if (dump)
    ebuf.dump();

  ebuf.add_ctrl_bo(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());
  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(),
    elf_patcher::buf_type::ctrltext, m_elf, m_kernel_index);

  io_test_bo_set_base::init_cmd(hwctx, dump);
}

void
async_error_aie4_io_test_bo_set::
verify_result()
{
  auto buf = device_query<query::xocl_errors>(m_dev);
  if (buf.empty())
    throw std::runtime_error("failed to get async errors, return empty information.");

  auto ect = query::xocl_errors::to_value(buf, XRT_ERROR_CLASS_AIE);
  xrtErrorCode err_code;
  xrtErrorTime err_timestamp;
  std::tie(err_code, err_timestamp) = ect;

  if (err_code != m_expect_err_code) {
    std::stringstream ss;
    ss << "failed to get async errors, unexpected error code, 0x" << std::hex << err_code
       << ", expected 0x" << m_expect_err_code << ".";
    throw std::runtime_error(ss.str());
  }

  if (err_timestamp == m_last_err_timestamp) {
    std::stringstream ss;
    ss << "failed to get async errors, return old timestamp: " << m_last_err_timestamp << ".";
    throw std::runtime_error(ss.str());
  }
  m_last_err_timestamp = err_timestamp;

  // Verify context health report in command packet (bad_ctrl.elf timeout path)
  auto cbo = m_bo_array[IO_TEST_BO_CMD].tbo.get();
  auto cpkt = reinterpret_cast<ert_packet *>(cbo->map());
  if (cpkt->state != ERT_CMD_STATE_TIMEOUT)
    return;

  auto cdata = reinterpret_cast<ert_ctx_health_data_v1 *>(cpkt->data);
  if (cdata->version != ERT_CTX_HEALTH_DATA_V1 || cdata->npu_gen != NPU_GEN_AIE4) {
    std::cerr << "Incorrect AIE4 context health data:\n";
    std::cerr << "\tversion: 0x" << std::hex << cdata->version
              << " (expect " << ERT_CTX_HEALTH_DATA_V1 << ")\n";
    std::cerr << "\tnpu_gen: 0x" << std::hex << cdata->npu_gen
              << " (expect " << NPU_GEN_AIE4 << ")\n";
    std::cerr << "\tctx_state: 0x" << std::hex << cdata->aie4.ctx_state << "\n";
    std::cerr << "\tnum_uc: " << std::dec << cdata->aie4.num_uc << "\n";
    throw std::runtime_error(std::string("Context health data version=") +
      std::to_string(cdata->version) + " npu_gen=" + std::to_string(cdata->npu_gen) +
      ", expect version=" + std::to_string(ERT_CTX_HEALTH_DATA_V1) +
      " npu_gen=" + std::to_string(NPU_GEN_AIE4));
  }
}

elf_io_aie_debug_test_bo_set::
elf_io_aie_debug_test_bo_set(device* dev, const std::string& tag, const flow_type* flow)
  : io_test_bo_set_base(dev, tag, flow)
{
  constexpr size_t COREDUMP_IFM_SIZE = 512 * 1024 * 4;
  constexpr size_t COREDUMP_WTS_SIZE = 20;
  const char* tag_c = tag.empty() ? nullptr : tag.c_str();
  m_is_full_elf = (get_flow_type(dev, tag_c, m_flow) == FULL_ELF);

  if (m_is_full_elf) {
    m_elf = xrt::elf(get_binary_path(dev, tag_c, m_flow));
    try {
      auto kernel_name = get_kernel_name(dev, tag_c, m_flow);
      m_kernel_index = m_elf.get_handle()->get_ctrlcode_id(kernel_name);
    } catch (const std::exception&) {
      m_kernel_index = elf_int::no_ctrl_code_id;
    }
  } else {
    std::filesystem::path elf_path(get_binary_path(dev, tag_c, m_flow));
    elf_path.replace_extension(".elf");
    m_elf = xrt::elf(elf_path.string());
    try {
      auto kernel_name = get_kernel_name(dev, tag_c, m_flow);
      m_kernel_index = m_elf.get_handle()->get_ctrlcode_id(kernel_name);
    } catch (const std::exception&) {
      m_kernel_index = elf_int::no_ctrl_code_id;
    }
  }

  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);

    switch(type) {
    case IO_TEST_BO_CMD:
      alloc_cmd_bo(ibo, m_dev);
      break;
    case IO_TEST_BO_INSTRUCTION:
      create_ctrl_bo_from_elf(ibo, elf_patcher::buf_type::ctrltext);
      break;
    case IO_TEST_BO_INPUT:
      alloc_data_bo(ibo, m_dev, COREDUMP_IFM_SIZE, false);
      {
        uint32_t* in = reinterpret_cast<uint32_t*>(ibo.tbo->map());
        for (int j = 0; j < static_cast<int>(COREDUMP_IFM_SIZE / sizeof(uint32_t)); ++j)
          in[j] = 0xdeadface;
      }
      break;
    case IO_TEST_BO_OUTPUT:
      alloc_data_bo(ibo, m_dev, COREDUMP_IFM_SIZE, false);
      break;
    case IO_TEST_BO_PARAMETERS:
      alloc_data_bo(ibo, m_dev, COREDUMP_WTS_SIZE, false);
      break;
    case IO_TEST_BO_2ND_PARAMETERS:
      alloc_data_bo(ibo, m_dev, COREDUMP_WTS_SIZE, false);
      break;
    default:
      break;
    }
  }
}

void
elf_io_aie_debug_test_bo_set::
init_cmd(hw_ctx& hwctx, bool dump)
{
  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), ERT_START_NPU);

  ebuf.set_cu_idx(get_cu_idx(hwctx));

  ebuf.add_arg_64(3);
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_INPUT].tbo.get(), "3");
  ebuf.add_arg_bo(*m_bo_array[IO_TEST_BO_OUTPUT].tbo.get(), "4");

  if (dump)
    ebuf.dump();

  ebuf.add_ctrl_bo(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());
  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(),
    elf_patcher::buf_type::ctrltext, m_elf, m_kernel_index);

  io_test_bo_set_base::init_cmd(hwctx, dump);
}

void
elf_io_aie_debug_test_bo_set::
verify_result()
{
  auto cbo = m_bo_array[IO_TEST_BO_CMD].tbo.get();
  auto cpkt = reinterpret_cast<ert_start_kernel_cmd *>(cbo->map());
  if (cpkt->state != ERT_CMD_STATE_COMPLETED)
    throw std::runtime_error(std::string("Coredump test command failed, state=") + std::to_string(cpkt->state));

  auto bo_ofm = m_bo_array[IO_TEST_BO_OUTPUT].tbo;
  if (!bo_ofm)
    return;
  bo_ofm->get()->sync(buffer_handle::direction::device2host, bo_ofm->size(), 0);
  auto out = reinterpret_cast<uint32_t *>(bo_ofm->map());
  auto size = bo_ofm->size();
  for (auto i = 0; i < static_cast<int>(size / 4); i++) {
    if (out[i] != 0xdeadface)
      throw std::runtime_error("Test Failed\n");
  }
}
