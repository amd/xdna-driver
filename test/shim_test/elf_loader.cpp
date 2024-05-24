// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <gelf.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "elf_loader.h"

#define LOCATION(C, P) (code.at(C).at(P).index + code.at(C).at(P).end)
#define FIRSTDOT 9
#define SECONDDOT 10

// These two are helper classes of an elf descriptor wrapping
// some C function calls.
class elf_fd
{
  public:
    elf_fd(const std::string& elf_fnm)
        :fd(open(elf_fnm.c_str(), O_RDONLY, 0))
    {
      if (fd < 0)
        throw std::runtime_error("Failed to open file '" + elf_fnm + "' for reading");
    }

    ~elf_fd()
    {
      close(fd);
    }

    int get_fd()
    {
      return fd;
    }

  private:
    int fd;
};

class elf_desc
{
  public:
    elf_desc(const std::string& elf_fnm)
        :efd{elf_fd(elf_fnm)}, elf{elf_begin(efd.get_fd(), ELF_C_READ, NULL)}
    {
      if (elf == nullptr)
        throw std::runtime_error("elf_begin() failed: " + std::string(elf_errmsg(-1)));
    }

    ~elf_desc()
    {
      elf_end(elf);
    }

    Elf* get_elf_ptr()
    {
      return elf;
    }

  private:
    elf_fd efd;
    Elf *elf;
};

struct page {
  uint32_t end;
  uint32_t index;
  uint32_t col_index;
  uint32_t text_size;
  uint32_t data_size;
};

static inline bool
is_ctrldata(const std::string &name)
{
  return !name.compare(0,9,".ctrldata");
}

static inline bool
is_ctrltext(const std::string &name)
{
  return !name.compare(0,9,".ctrltext");
}

static inline int
getcol(const std::string &name)
{
  int first = name.find_first_of(".", FIRSTDOT) + 1;
  int len = name.find_first_of(".", SECONDDOT) - first;
  return std::stoi(name.substr(first, len));
}

static inline int
getpagenum(const std::string &name)
{
  return std::stoi(name.substr(name.find_first_of(".", SECONDDOT) + 1));
}

static void
resize(Elf* e, size_t shstrndx, std::vector<ctrl_code> &rctrl, std::vector<std::vector<struct page>> &code)
{
  Elf_Scn *scn = NULL;
  std::vector<int> numpages;
  int activecol = 0;
  while ((scn = elf_nextscn(e, scn)) != NULL) {
    GElf_Shdr shdr;
    if (gelf_getshdr(scn, &shdr) == NULL)
      throw std::runtime_error("getshdr() failed: " + std::string(elf_errmsg(elf_errno())));

    const std::string name = std::string(elf_strptr(e, shstrndx, shdr.sh_name));

    Elf_Data *data = NULL;
    if ((data = elf_getdata(scn, data)) == NULL)
      throw std::runtime_error("elf_getdata failed: " + std::string(elf_errmsg(-1)));

    if (is_ctrltext(name) || is_ctrldata(name)) {
      int col = getcol(name);
      int pagenum = getpagenum(name);
      if (col >= numpages.size()) {
        numpages.resize(col+1, 0);
        code.resize(col+1);
        activecol++;
      }

      if (pagenum+1 >= numpages[col]) {
        numpages[col] = pagenum + 1;
        code.at(col).resize(pagenum+1);
      }

      if (is_ctrltext(name))
        code.at(col).at(pagenum).text_size = data->d_size;
      if (is_ctrldata(name))
        code.at(col).at(pagenum).data_size = data->d_size;
    }
  }

  rctrl.resize(activecol);
  int col = 0;
  for (size_t i = 0; i < numpages.size(); i++) {
    uint32_t total = 0;
    if (numpages.at(i) > 0) {
      for (size_t k = 0; k < numpages.at(i); k++) {
        code.at(i).at(k).index = total;
        total += code.at(i).at(k).text_size + code.at(i).at(k).data_size;
        code.at(i).at(k).col_index = col;
      }

      rctrl.at(col).ccode.resize(total, 0);
      col++;
    }
  }
}

enum class Kind
{
  UC_DMA_REMOTE_PTR_SYMBOL_KIND = 1,
  SHIM_DMA_BASE_ADDR_SYMBOL_KIND = 2,
  SCALAR_32BIT_KIND = 3,
  UNKNOWN_SYMBOL_KIND = 4
};

static void
patch_57(uint32_t *bd_data_ptr, uint64_t patch)
{
  uint64_t base_address = (((uint64_t)bd_data_ptr[8] & 0x1FF) << 48) | (((uint64_t)bd_data_ptr[2] & 0xFFFF) << 32) | bd_data_ptr[1];
  base_address += patch;
  bd_data_ptr[1] = (uint32_t)(base_address & 0xFFFFFFFF);
  bd_data_ptr[2] = (bd_data_ptr[2] & 0xFFFF0000) | ((base_address >> 32) & 0xFFFF);
  bd_data_ptr[8] = (bd_data_ptr[8] & 0xFFFFFE00) | ((base_address >> 48) & 0x1FF);
}

static void
patch_32(uint32_t *bd_data_ptr, uint64_t patch)
{
  uint64_t base_address = bd_data_ptr[0];
  base_address += patch;
  bd_data_ptr[0] = (uint32_t)(base_address & 0xFFFFFFFF);
}

static std::vector<ctrl_code>
el_get_from_file(const std::string& elf_fnm, const std::map<std::string, uint64_t>& symbols)
{
  if (elf_version(EV_CURRENT) == EV_NONE)
    throw std::runtime_error("ELF library initialization failed: " + std::string(elf_errmsg(-1)));

  elf_desc eld(elf_fnm);
  auto e = eld.get_elf_ptr();
  if (elf_kind(e) != ELF_K_ELF)
    throw std::runtime_error(elf_fnm + "is not an ELF object");

  std::vector<ctrl_code> rctrl;

  size_t shstrndx;
  if (elf_getshdrstrndx(e, &shstrndx) != 0)
    throw std::runtime_error("elf_getshdrstrndx() failed: " + std::string(elf_errmsg(-1)));

  Elf_Scn *scn = NULL;
  std::vector<Elf32_Rela> relas;
  std::vector<Elf32_Sym> dynsyms;
  std::map<std::string, Elf32_Sym> dynsymmap;
  std::vector<std::string> symnames;
  int dynstrindex = 0;
  std::vector<std::vector<struct page>> code; // to hold page info

  resize(e, shstrndx, rctrl, code);

  while ((scn = elf_nextscn(e, scn)) != NULL) {
    GElf_Shdr shdr;
    if (gelf_getshdr(scn, &shdr) != &shdr)
      throw std::runtime_error("getshdr() failed: " + std::string(elf_errmsg(-1)));

    std::string name = std::string(elf_strptr(e, shstrndx, shdr.sh_name));

    Elf_Data *data = NULL;
    if ((data = elf_getdata(scn, data)) == NULL)
      throw std::runtime_error("elf_getdata failed: " + std::string(elf_errmsg(-1)));

    if (is_ctrltext(name)) {
      int col = getcol(name);
      int pagenum = getpagenum(name);
      uint32_t index = code.at(col).at(pagenum).col_index;
      rctrl.at(index).col = col;
      std::copy_n(reinterpret_cast<char *>(data->d_buf), data->d_size, rctrl.at(index).ccode.begin() + LOCATION(col, pagenum));
      code.at(col).at(pagenum).end = data->d_size;
      continue;
    }

    if (is_ctrldata(name)) {
      int col = getcol(name);
      int pagenum = getpagenum(name);
      uint32_t index = code.at(col).at(pagenum).col_index;
      std::copy_n(reinterpret_cast<char *>(data->d_buf), data->d_size, rctrl.at(index).ccode.begin() + LOCATION(col, pagenum));
      code.at(col).at(pagenum).end += data->d_size;
      continue;
    }

    if (!name.compare(".rela.dyn")) {
      relas.insert(relas.end(), reinterpret_cast<Elf32_Rela *>(data->d_buf), reinterpret_cast<Elf32_Rela *>(data->d_buf) + data->d_size / sizeof (Elf32_Rela));
      continue;
    }

    if (!name.compare(".dynsym")) {
      dynsyms.insert(dynsyms.end(), reinterpret_cast<Elf32_Sym *>(data->d_buf), reinterpret_cast<Elf32_Sym *>(data->d_buf) + data->d_size / sizeof (Elf32_Sym));
      continue;
    }

    if (!name.compare(".dynstr")) {
      dynstrindex = elf_ndxscn(scn);
      auto p = reinterpret_cast<char *>(data->d_buf);
      while (p != nullptr && p < reinterpret_cast<char *>(data->d_buf) + data->d_size) {
        char *np = strchr(p, '\0');
        symnames.emplace_back(p);
        p = np + 1;
      }
      continue;
    }
  }

  // Patch symbols
  for (Elf32_Rela rela : relas) {
    uint32_t symidx = ELF32_R_SYM(rela.r_info);
    auto search = symbols.find(symnames.at(symidx));
    if (search == symbols.end())
      throw std::runtime_error("symbol: " + symnames.at(symidx) + " not found");

    if (symidx > dynsyms.size())
      throw std::runtime_error("symbol: " + symnames.at(symidx) + " with symidx not found dynsym");

    auto dy = dynsyms.at(symidx);

    // Get Page number and col number from st_shndx
    scn = elf_getscn(e, dy.st_shndx);
    if (scn == NULL)
      throw std::runtime_error("symbol: " + symnames.at(symidx) + " elf_getscn() failed: " + std::string(elf_errmsg(elf_errno())));

    GElf_Shdr shdr;
    if (gelf_getshdr(scn, &shdr) == NULL)
      throw std::runtime_error("symbol: " + symnames.at(symidx) + " getshdr() failed: " + std::string(elf_errmsg(elf_errno())));

    std::string name = std::string(elf_strptr(e, shstrndx, shdr.sh_name));

    int col = getcol(name);
    int pagenum = getpagenum(name);
    uint32_t index = code.at(col).at(pagenum).col_index;
    auto p = rctrl.at(index).ccode.data() + code.at(col).at(pagenum).index;
    // We need to add 16 bytes control code header
    auto bd_data_ptr = reinterpret_cast<uint32_t *>(p + rela.r_offset + 16);
    // use specific relocation based on r_addend.
    // SCALAR_32BIT_KIND patch 32bit value
    // SHIM_DMA_BASE_ADDR_SYMBOL_KIND patch 57bit UC_DMA_SHIM_BD address
    auto kind = static_cast<Kind>(rela.r_addend);
    switch(kind) {
      case Kind::SCALAR_32BIT_KIND: patch_32(bd_data_ptr, search->second);
      break;
      case Kind::SHIM_DMA_BASE_ADDR_SYMBOL_KIND: patch_57(bd_data_ptr, search->second);
      break;
      default: throw std::runtime_error("Unsupported rela.r_addend for symbol: " + symnames.at(symidx));
    }
  }

  return rctrl;
}

std::vector<ctrl_code>
get_ctrl_from_elf(const std::string& elf_fnm, const std::map<std::string, uint64_t>& symbols)
{
  try {
    return el_get_from_file(elf_fnm, symbols);
  }
  catch (const std::exception& ex) {
    std::cerr << ex.what() << std::endl;
    throw;
  }
}
