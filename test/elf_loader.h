// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _ELF_LOADER_H_
#define _ELF_LOADER_H_

#include <map>
#include <string>
#include <vector>

/*!
 * @class crtl_code
 * @brief
 * The ctrl_code class represents the control code binary which
 * can be loaded to AIE2PS and executed by each columns' controller.
 */
class ctrl_code
{
  public:
    uint32_t          col;         // column number
    std::vector<char> ccode;       // ctrl code binary
};

/*!
 * This API takes an ELF format control code file of a partition and
 * a map containing the symbols and its address to be patched in ELF.
 * It returns an vector of ctrl_code with patched addresses.
 * Each element in the vector represents a coloumn (uint32_t) and its
 * control code binary (vector)
 *
 * @elf_fnm:    ELF file name
 * @symbols:    std::map of symbol name and its address to be patched
 *
 * Return:  The vector ctrl_code containing patched control code of each
 *          column
 */
std::vector<ctrl_code>
get_ctrl_from_elf(const std::string& elf_fnm, const std::map<std::string, uint64_t>& symbols);

#endif // _ELF_LOADER_H_
