// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023, Advanced Micro Devices, Inc. All rights reserved.

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

namespace {

std::string instr_file("mc_code.txt");
std::string ifm_file("ifm.bin");
std::string param_file("param.bin");
std::string mc_blob_file("mc_code_ddr.bin");
std::string ofm_gold_file("golden_dwconv0_fix.bin");
std::string ofm_dump_file("ofm_ddr_dump.txt");
std::string config_file("ddr_range.txt");
std::string ofm_format_file("ofm_format.txt");
std::string dump_inter_file("dump_inter.bin");

size_t get_instr_size(const std::string& fname)
{
    std::ifstream myfile(fname);
    size_t ret = 0;

    if (!myfile.is_open())
      throw std::runtime_error("cannot open instr file");

    std::string line;
    while (getline(myfile, line)) {
      if (line.at(0) == '#')
        continue;
      ret++;
    }
    myfile.close();

    return ret;
}

// Copy DPU instructions from text file into a buffer
void read_instructions_from_txt(const std::string& fname, int* buf)
{
    std::ifstream myfile(fname);
    unsigned int value;
    std::string line;
    size_t ret = 0;

    if (!myfile.is_open())
      throw std::runtime_error("cannot open instr file");

    while (getline(myfile, line)) {
      if (line.at(0) == '#')
        continue;

      std::stringstream ss(line);
      ss >> std::hex >> value;
      *(buf++) = value;
    }
    myfile.close();
}

#define IFM_DIRTY_BYTES(t) std::get<0>(t)
#define IFM_SIZE(t)        std::get<1>(t)
#define PARAM_SIZE(t)      std::get<2>(t)
#define OFM_SIZE(t)        std::get<3>(t)
#define INTER_SIZE(t)      std::get<4>(t)
#define MC_CODE_SIZE(t)    std::get<5>(t)
#define DUMMY_MC_CODE_BUFFER_SIZE (16UL) // use in case buffer doesn't exist, in bytes

std::tuple<int, int, int, int, int, int>
parse_config_file(const std::string& fname)
{
  std::ifstream myfile(fname);
  int ifm_addr = 0;
  int ifm_size = 0;
  int param_size = 0;
  int ofm_size = 0;
  int inter_size = 0;
  int mc_code_size = 0;
  std::string line;

  if (!myfile.is_open())
    throw std::runtime_error("cannot open config file: " + fname);

  inter_size = 1024*1024;
  while (getline (myfile,line)) {
    unsigned int value = 0;
    std::string field;
    std::stringstream ss(line);

    ss >> field >> value;
    if (field == "ifm_addr") {
      ifm_addr = value;
    } else if (field == "ifm_size") {
      ifm_size = value;
    } else if (field == "param_addr") {
      if (value)
        throw std::runtime_error("not expecting non-zero param_addr");
    } else if (field == "param_size") {
      if (value)
        param_size = value;
      else
        param_size = 64; // some tests do not have param. Zero buffer size will fail at buffer allocation
    } else if (field == "inter_addr") {
      if (value)
        throw std::runtime_error("not expecting non-zero inter_addr");
    } else if (field == "inter_size") {
      if (value)
          inter_size = value;
    } else if (field == "ofm_addr") {
      if (value)
        throw std::runtime_error("not expecting non-zero ofm_addr");
    } else if (field == "ofm_size") {
      ofm_size = value;
    } else if (field == "mc_code_addr") {
      if (value)
        throw std::runtime_error("not expecting non-zero mc_code_addr");
    } else if (field == "mc_code_size") {
      mc_code_size = value;
    } else {
      throw std::runtime_error("parse config file error");
    }
  }

  myfile.close();
  return std::make_tuple(ifm_addr, ifm_size, param_size, ofm_size, inter_size, mc_code_size);
}

void read_data_from_bin(const std::string& fname, size_t offset, size_t size, int* buf)
{
  std::ifstream myfile(fname, std::ios::in | std::ios::binary);

  if (!myfile.is_open())
    throw std::runtime_error("cannot open file: " + fname);

  buf += offset/sizeof(int);
  myfile.read((char *)buf, size);
}

int comp_buf_strides(int8_t *buff, std::string &goldenFile, std::string &dumpFile,
                     std::vector<unsigned> shapes, std::vector<unsigned> strides)
{
  std::ifstream ifs(goldenFile, std::ios::in | std::ios::binary);

  if (!ifs.is_open())
    throw std::runtime_error("Failed to open golden file");
  
  std::ofstream ofs(dumpFile, std::ios::out | std::ios::binary);
  
  std::string s("Failed to open dump file: ");
  if (!ofs.is_open())
    throw std::runtime_error(s + dumpFile);

  std::istreambuf_iterator<char> it(ifs), end;

  int ret = 0;
  for (int n = 0; n < shapes[0]; n++)
    for (int h = 0; h < shapes[1]; h++)
      for (int w = 0; w < shapes[2]; w++)
        for (int c = 0; c < shapes[3]; c++) {
          auto idx = n*strides[0] + h*strides[1] + w*strides[2] + c*strides[3];
          char byt = *it;

          if (byt != buff[idx]) {
            printf("Bytes differ at index %d: expect %d, saw %d\n", idx, byt, buff[idx]);
            ret = 1; 
          }
          ofs.write((char*)(&(buff[idx])), 1);
          it++;
        }

  return ret;
}

int verify_output(int8_t* buf, const std::string &wrk_path)
{
  std::ifstream myfile(wrk_path + ofm_format_file);

  if (!myfile.is_open())
      throw std::runtime_error("Can't open ofm_format");

  unsigned num_outputs = 0;
  std::vector<std::string> golden_output_files;
  std::vector<std::string> dump_output_files;
  std::vector<unsigned> output_ddr_addr;
  std::vector<std::vector<unsigned>> output_shapes;
  std::vector<std::vector<unsigned>> output_strides;
  std::string line;
  std::string key;
  std::string str_val;
  unsigned int_val;

  getline(myfile, line);
  std::stringstream ss(line);
  ss >> key >> num_outputs;
  ss.clear();
  if (num_outputs > 10000)
      throw std::runtime_error("num_outputs is too big");

  for (int i = 0; i < num_outputs; i++) {
    getline(myfile, line);
    ss.str(line);
    ss >> key >> str_val;
    ss.clear();
    golden_output_files.push_back(wrk_path + "golden_" + str_val + ".bin");
    dump_output_files.push_back("/tmp/dump_" + str_val + "." + std::to_string(getpid()) + ".bin");

    getline(myfile, line);
    ss.str(line);
    ss >> key >> int_val;
    ss.clear();
    output_ddr_addr.push_back(int_val);

    std::vector<unsigned> shapes;
    for (int j = 0; j < 4; j++) {
      getline(myfile, line);
      ss.str(line);
      ss >> key >> int_val;
      ss.clear();
      shapes.push_back(int_val);
    }
    output_shapes.push_back(std::move(shapes));

    std::vector<unsigned> strides;
    for (int j = 0; j < 4; j++) {
      getline(myfile, line);
      ss.str(line);
      ss >> key >> int_val;
      ss.clear();
      strides.push_back(int_val);
    }
    output_strides.push_back(std::move(strides));
  }

  int ret = 0;
  for (int i = 0; i < num_outputs; i++) {
    ret = comp_buf_strides(buf + output_ddr_addr[i], golden_output_files[i],
                           dump_output_files[i], output_shapes[i], output_strides[i]);
    if (ret) {
        std::cout << "Examing failed, ret " << ret << std::endl;
        std::cout << "Examing output: " << dump_output_files[i] << std::endl;
        break;
    } else {
        if (std::remove(dump_output_files[i].c_str()))
            std::cout << "Failed to remove " << dump_output_files[i] << std::endl;
    }
  }

  return ret;
}

void dump_buf_to_file(int8_t *buf, size_t size, const std::string& dumpfile)
{
    std::ofstream ofs(dumpfile, std::ios::out | std::ios::binary);
    std::string s("Failed to open dump file: ");
    if (!ofs.is_open())
        throw std::runtime_error(s + dumpfile);

    for (int i = 0; i < size; i++) {
        ofs.write((char*)(&(buf[i])), 1);
    }
}

}

#endif // _CONFIG_H_
