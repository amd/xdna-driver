// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024-2025, Advanced Micro Devices, Inc. All rights reserved.

#include "io.h"
#include "hwctx.h"
#include "io_config.h"
#include "core/common/aiebu/src/cpp/include/aiebu/aiebu_assembler.h"

#include <climits>
#include <string>
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
    throw std::runtime_error("Can't open TXN bin file?");

  std::unique_ptr<aiebu::aiebu_assembler> asp = nullptr;
  if (pm_ctrlpkt_buf.size()) {
    std::vector<char> buffer2 = {};
    std::vector<char> patch_json = {};
    std::vector<std::string> libs = { "preempt" };
    std::vector<std::string> libpaths = { get_preemption_libs_path() };
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
  return elf_int::get_partition_size(elf);
}

} // namespace

io_test_bo_set_base::
io_test_bo_set_base(device* dev, const std::string& xclbin_name) :
  m_bo_array{}
  , m_xclbin_name(xclbin_name)
  , m_local_data_path(get_xclbin_data(dev, xclbin_name.c_str()))
  , m_dev(dev)
  , m_kernel_index(module_int::no_ctrl_code_id)
{
}

void
io_test_bo_set_base::
create_data_bo_from_file(io_test_bo& ibo, const std::string filename, int flags)
{
  auto file = m_local_data_path + "/" + filename;
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
create_ctrl_bo_from_elf(io_test_bo& ibo, xrt_core::patcher::buf_type type)
{
  auto size = exec_buf::get_ctrl_code_size(m_elf, type, m_kernel_index);
  if (size == 0)
    throw std::runtime_error("instruction size cannot be 0");
  alloc_ctrl_bo(ibo, m_dev, size);
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
io_test_bo_set(device* dev) : io_test_bo_set(dev, get_xclbin_name(dev), false)
{
}

io_test_bo_set::
io_test_bo_set(device* dev, bool use_ubuf) : io_test_bo_set(dev, get_xclbin_name(dev), use_ubuf)
{
}

elf_io_test_bo_set::
elf_io_test_bo_set(device* dev, const std::string& xclbin_name) :
  io_test_bo_set_base(dev, xclbin_name)
{
  std::string file;

  m_elf = txn_file2elf(m_local_data_path + "/ml_txn.bin", m_local_data_path + "/pm_ctrlpkt.bin");

  for (int i = 0; i < IO_TEST_BO_MAX_TYPES; i++) {
    auto& ibo = m_bo_array[i];
    auto type = static_cast<io_test_bo_type>(i);
    size_t size;

    switch(type) {
    case IO_TEST_BO_CMD:
      alloc_cmd_bo(ibo, m_dev);
      break;
    case IO_TEST_BO_INSTRUCTION:
      create_ctrl_bo_from_elf(ibo, patcher::buf_type::ctrltext);
      break;
    case IO_TEST_BO_INPUT:
      create_data_bo_from_file(ibo, "ifm.bin", 0);
      break;
    case IO_TEST_BO_PARAMETERS:
      create_data_bo_from_file(ibo, "wts.bin", m_FLAG_OPT);
      break;
    case IO_TEST_BO_OUTPUT:
      create_data_bo_from_file(ibo, "ofm.bin", m_FLAG_NO_FILL);
      break;
    case IO_TEST_BO_CTRL_PKT_PM:
      create_data_bo_from_file(ibo, "pm_ctrlpkt.bin", m_FLAG_OPT);
      break;
    default:
      break;
    }
  }
}

elf_preempt_io_test_bo_set::
elf_preempt_io_test_bo_set(device* dev, const std::string& xclbin_name)
  : io_test_bo_set_base(dev, xclbin_name)
  , m_is_full_elf(get_kernel_type(dev, xclbin_name.c_str()) == KERNEL_TYPE_TXN_FULL_ELF_PREEMPT)
  , m_total_fine_preemption_checkpoints(get_fine_preemption_checkpoints(m_local_data_path + "/ml_txn.bin"))
{
  std::string file;

  if (m_is_full_elf) {
    m_elf = xrt::elf(get_xclbin_path(dev, xclbin_name.c_str()));
    auto nm = get_kernel_name(dev, xclbin_name.c_str());
    auto mod = xrt::module{m_elf};
    m_kernel_index = module_int::get_ctrlcode_id(mod, std::string(nm));
  } else {
    m_elf = txn_file2elf(m_local_data_path + "/ml_txn.bin", m_local_data_path + "/pm_ctrlpkt.bin");
    m_kernel_index = module_int::no_ctrl_code_id;
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
      create_ctrl_bo_from_elf(ibo, patcher::buf_type::ctrltext);
      break;
    case IO_TEST_BO_SAVE_INSTRUCTION:
      create_ctrl_bo_from_elf(ibo, patcher::buf_type::preempt_save);
      break;
    case IO_TEST_BO_RESTORE_INSTRUCTION:
      create_ctrl_bo_from_elf(ibo, patcher::buf_type::preempt_restore);
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

      if (get_kernel_type(dev, xclbin_name.c_str()) == KERNEL_TYPE_TXN_FULL_ELF_PREEMPT)
        size = mem_tile_sz * get_column_size(m_elf);
      else
        size = mem_tile_sz * get_column_size(xrt::xclbin(get_xclbin_path(dev, xclbin_name.c_str())));
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
init_cmd(cuidx_type idx, bool dump)
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
init_cmd(cuidx_type idx, bool dump)
{
  exec_buf ebuf(*m_bo_array[IO_TEST_BO_CMD].tbo.get(), ERT_START_NPU);

  ebuf.set_cu_idx(idx);

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

  ebuf.add_ctrl_bo(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get());
  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_INSTRUCTION].tbo.get(),
    patcher::buf_type::ctrltext, m_elf, module_int::no_ctrl_code_id);
}

void
elf_preempt_io_test_bo_set::
init_cmd(cuidx_type idx, bool dump)
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
    ebuf.set_cu_idx(idx);

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
    patcher::buf_type::ctrltext, m_elf, m_kernel_index);
  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_SAVE_INSTRUCTION].tbo.get(),
    patcher::buf_type::preempt_save, m_elf, m_kernel_index);
  ebuf.patch_ctrl_code(*m_bo_array[IO_TEST_BO_RESTORE_INSTRUCTION].tbo.get(),
    patcher::buf_type::preempt_restore, m_elf, m_kernel_index);
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
