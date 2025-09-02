#! /bin/bash -

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2025 AMD, Inc. All rights reserved.

set -euo pipefail

usage()
{
  cat << USAGE_END
Usage: build.sh [options]
Options:
  -help                   Display this help
  -clean                  Clean build directory
  -debug                  Debug build and generate .deb package
  -release                Release build and generate .deb package
  -example                Example build
  -package                Ignored (present for backward compatibility)
  -j <n>                  Compile parallel (default: num of CPUs)
  -nocmake                Do not regenerate cmake files
  -install_prefix <path>  Set CMAKE_INSTALL_PREFIX to path"
  -verbose                Enable verbose build
  -hello_umq              Hello UMQ Memory Test
  -dir                    Download directory if apply
  -nokmod                 Don't build or install the kernel module
USAGE_END
}

usage_and_exit()
{
  usage
  exit 1
}

is_not_option_or_empty()
{
  arg=$1

  if [[ "$arg" == "" || "$arg" == -* ]]; then
    return 1
  fi

  return 0
}

build_targets()
{
  BUILD_TYPE=$1
  mkdir -p $BUILD_TYPE
  cd  $BUILD_TYPE
  if [[ $nocmake == 0 ]]; then
    # Some git submodule dir's ownershipt may not be right, fix it
    # so that cmake generation can be done properly
    git config --global --add safe.directory '*'
    time $CMAKE $cmake_extra_flags -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DUMQ_HELLO_TEST=$hello_umq $BUILD_DIR/../
  fi
  time make -j $njobs $verbose DESTDIR=$PWD install

  cd ..
}

package_targets()
{
  BUILD_TYPE=$1

  if [ ! -d $BUILD_TYPE ]; then
    echo "Nothing to be done for $BUILD_TYPE build"
    return
  fi

  cd  $BUILD_TYPE
  time make -j $njobs $verbose DESTDIR=$PWD package

  cd ..
}

build_example()
{

  mkdir -p $EXAMPLE_BUILD_DIR
  cd $EXAMPLE_BUILD_DIR

  time $CMAKE $BUILD_DIR/../example/
  time make

  cd ..
}

download_npufws()
{
  local firmware_dir=${DOWNLOAD_BINS_DIR}/firmware

  jq -c '.firmwares[]' "$INFO_JSON" |
    while IFS= read -r line; do
      local device=$(echo $line | jq -r '.device')
      local pci_dev_id=$(echo $line | jq -r '.pci_device_id')
      local version=$(echo $line | jq -r '.version')
      local fw_name=$(echo $line | jq -r '.fw_name')
      local url=$(echo $line | jq -r '.url')
      local pci_rev_id=$(echo $line | jq -r '.pci_revision_id')

      if [[ -z "$url" ]]; then
        echo "Empty URL for $device NPUFW, SKIP."
        continue
      fi

      echo "Download $device NPUFW version $version:"
      if [ -d "${firmware_dir}/${pci_dev_id}_${pci_rev_id}" ]; then
        rm -r ${firmware_dir}/${pci_dev_id}_${pci_rev_id}
      fi
      mkdir -p ${firmware_dir}/${pci_dev_id}_${pci_rev_id}
      wget -O ${firmware_dir}/${pci_dev_id}_${pci_rev_id}/$fw_name $url

    done
}

do_build()
{
  BUILD_TYPE=$1
  build_targets $BUILD_TYPE
  if [[ $nocmake == 0 ]]; then
    # No need to download firmware if driver build is skipped
    if [[ $skip_kmod == 0 ]]; then
      download_npufws
    fi
    # Prepare xbutil validate related files for packaging
    mkdir -p $XBUTIL_VALIDATE_BINS_DIR
    cp -r ../tools/bins/* $XBUTIL_VALIDATE_BINS_DIR
    package_targets $BUILD_TYPE
  fi
}

# Config variables
clean=0
distclean=0
debug=1
release=0
package=0
example=0
nocmake=0
verbose=
skip_kmod=0
njobs=`grep -c ^processor /proc/cpuinfo`
download_dir=
xrt_install_prefix="/opt/xilinx/xrt"
hello_umq=n

while [ $# -gt 0 ]; do
  case "$1" in
    -help | -h)
      usage
      exit 0
      ;;
    -clean | clean)
      clean=1
      ;;
    -distclean | distclean)
      clean=1
      distclean=1
      ;;
    -debug)
      debug=1
      release=0
      ;;
    -release)
      debug=0
      release=1
      ;;
    -example)
      example=1
      ;;
    -package)
      package=1
      debug=0
      release=0
      ;;
    -j)
      if is_not_option_or_empty $2; then
        njobs=$2
        shift
      fi
      ;;
    -nocmake)
      nocmake=1
      ;;
    -hello_umq)
      hello_umq=y
      ;;
    -verbose)
      verbose=VERBOSE=1
      ;;
    -nokmod)
      skip_kmod=1
      ;;
    -dir)
      download_dir=$2
      shift
      ;;
    -install_prefix)
      if is_not_option_or_empty $2; then
        xrt_install_prefix=$2
        shift
      fi
      ;;
    *)
      echo "unknown option"
      usage_and_exit
      ;;
  esac
  shift
done

OSDIST=`grep '^ID=' /etc/os-release | awk -F= '{print $2}' | tr -d '"'`
BUILD_DIR=$(readlink -f $(dirname ${BASH_SOURCE[0]}))
DEBUG_BUILD_TYPE=Debug
RELEASE_BUILD_TYPE=Release
CMAKE=cmake
CMAKE_MAJOR_VERSION=`cmake --version | head -n 1 | awk '{print $3}' |awk -F. '{print $1}'`
cmake_extra_flags=""
EXAMPLE_BUILD_DIR=example_build
INFO_JSON=${BUILD_DIR}/../tools/info.json
DOWNLOAD_BINS_DIR=./amdxdna_bins
XBUTIL_VALIDATE_BINS_DIR=$DOWNLOAD_BINS_DIR/download_raw/xbutil_validate/bins

# Sanity check
if [[ $CMAKE_MAJOR_VERSION != 3 ]]; then
    if [[ $OSDIST == "centos" ]] || [[ $OSDIST == "amzn" ]] || [[ $OSDIST == "rhel" ]] || [[ $OSDIST == "fedora" ]]; then
        CMAKE=cmake3
        if [[ ! -x "$(command -v $CMAKE)" ]]; then
            echo "$CMAKE is not installed"
            exit 1
        fi
    fi
fi
# Sanity check end

cmake_extra_flags+=" -DCMAKE_INSTALL_PREFIX=$xrt_install_prefix"
cmake_extra_flags+=" -DSKIP_KMOD=$skip_kmod"

if [[ ! -z "$download_dir" ]]; then
  echo "Specified download directory is $download_dir"
  DOWNLOAD_BINS_DIR=$download_dir
fi

if [[ $clean == 1 ]]; then
  echo "Only clean the build directory, will not perform other options if apply"
  rm -rf $DEBUG_BUILD_TYPE $RELEASE_BUILD_TYPE $EXAMPLE_BUILD_DIR
  if [[ $distclean == 1 ]]; then
    rm -rf ${DOWNLOAD_BINS_DIR}
  fi
  exit 0
fi

if [[ $example == 1 ]]; then
  build_example
  exit 0
fi

# Update xrt-smi validate related files from vtd
cp -f ../vtd/xclbin_prod/validate_npu4.xclbin ../tools/bins/17f0_10/validate.xclbin
cp -f ../vtd/xclbin_prod/validate_npu4.xclbin ../tools/bins/17f0_11/validate.xclbin
cp -f ../vtd/xclbin_prod/validate_npu4.xclbin ../tools/bins/17f0_20/validate.xclbin
cp -f ../vtd/xclbin_prod/validate_elf_npu4.xclbin ../tools/bins/17f0_10/validate_elf.xclbin
cp -f ../vtd/xclbin_prod/validate_elf_npu4.xclbin ../tools/bins/17f0_11/validate_elf.xclbin
cp -f ../vtd/xclbin_prod/validate_elf_npu4.xclbin ../tools/bins/17f0_20/validate_elf.xclbin
cp -f ../vtd/xclbin_prod/preemption_4x4_npu4.xclbin ../tools/bins/17f0_10/preemption_4x4.xclbin
cp -f ../vtd/xclbin_prod/preemption_4x4_npu4.xclbin ../tools/bins/17f0_11/preemption_4x4.xclbin
cp -f ../vtd/xclbin_prod/preemption_4x4_npu4.xclbin ../tools/bins/17f0_20/preemption_4x4.xclbin
cp -f ../vtd/xclbin_prod/preemption_4x8_npu4.xclbin ../tools/bins/17f0_10/preemption_4x8.xclbin
cp -f ../vtd/xclbin_prod/preemption_4x8_npu4.xclbin ../tools/bins/17f0_11/preemption_4x8.xclbin
cp -f ../vtd/xclbin_prod/preemption_4x8_npu4.xclbin ../tools/bins/17f0_20/preemption_4x8.xclbin
cp -f ../vtd/xclbin_prod/mobilenet_elf_npu4_4x4.xclbin ../tools/bins/17f0_10/mobilenet_4col.xclbin
cp -f ../vtd/xclbin_prod/mobilenet_elf_npu4_4x4.xclbin ../tools/bins/17f0_11/mobilenet_4col.xclbin
cp -f ../vtd/xclbin_prod/mobilenet_elf_npu4_4x4.xclbin ../tools/bins/17f0_20/mobilenet_4col.xclbin
cp -f ../vtd/xclbin_prod/validate_npu.xclbin ../tools/bins/1502_00/validate.xclbin
cp -f ../vtd/elf/nop_npu4.elf ../tools/bins/17f0_10/nop.elf
cp -f ../vtd/elf/nop_npu4.elf ../tools/bins/17f0_11/nop.elf
cp -f ../vtd/elf/nop_npu4.elf ../tools/bins/17f0_20/nop.elf
cp -f ../vtd/elf/preemption_noop_4x4.elf ../tools/bins/17f0_10/preemption_noop_4x4.elf
cp -f ../vtd/elf/preemption_noop_4x4.elf ../tools/bins/17f0_11/preemption_noop_4x4.elf
cp -f ../vtd/elf/preemption_noop_4x4.elf ../tools/bins/17f0_20/preemption_noop_4x4.elf
cp -f ../vtd/elf/preemption_noop_4x8.elf ../tools/bins/17f0_10/preemption_noop_4x8.elf
cp -f ../vtd/elf/preemption_noop_4x8.elf ../tools/bins/17f0_11/preemption_noop_4x8.elf
cp -f ../vtd/elf/preemption_noop_4x8.elf ../tools/bins/17f0_20/preemption_noop_4x8.elf
cp -f ../vtd/elf/preemption_memtile_4x4.elf ../tools/bins/17f0_10/preemption_memtile_4x4.elf
cp -f ../vtd/elf/preemption_memtile_4x4.elf ../tools/bins/17f0_11/preemption_memtile_4x4.elf
cp -f ../vtd/elf/preemption_memtile_4x4.elf ../tools/bins/17f0_20/preemption_memtile_4x4.elf
cp -f ../vtd/elf/preemption_memtile_4x8.elf ../tools/bins/17f0_10/preemption_memtile_4x8.elf
cp -f ../vtd/elf/preemption_memtile_4x8.elf ../tools/bins/17f0_11/preemption_memtile_4x8.elf
cp -f ../vtd/elf/preemption_memtile_4x8.elf ../tools/bins/17f0_20/preemption_memtile_4x8.elf
cp -f ../vtd/elf/mobilenet_4col.elf ../tools/bins/17f0_10/mobilenet_4col.elf
cp -f ../vtd/elf/mobilenet_4col.elf ../tools/bins/17f0_11/mobilenet_4col.elf
cp -f ../vtd/elf/mobilenet_4col.elf ../tools/bins/17f0_20/mobilenet_4col.elf
cp -f ../vtd/input_data/mobilenet/mobilenet_ifm.bin ../tools/bins/Mobilenet/mobilenet_ifm.bin
cp -f ../vtd/input_data/mobilenet/mobilenet_param.bin ../tools/bins/Mobilenet/mobilenet_param.bin
cp -f ../vtd/input_data/mobilenet/buffer_sizes.json ../tools/bins/Mobilenet/buffer_sizes.json

cp -f ../vtd/runner/throughput/phx/recipe_throughput_phx.json ../tools/bins/Runner/throughput/recipe_throughput_phx.json
cp -f ../vtd/runner/throughput/phx/validate_throughput_phx.xclbin ../tools/bins/Runner/throughput/validate_throughput_phx.xclbin
cp -f ../vtd/runner/throughput/phx/profile_throughput_phx.json ../tools/bins/Runner/throughput/profile_throughput_phx.json
cp -f ../vtd/runner/throughput/strx/recipe_throughput_strx.json ../tools/bins/Runner/throughput/recipe_throughput_strx.json
cp -f ../vtd/runner/throughput/strx/validate_throughput_strx.xclbin ../tools/bins/Runner/throughput/validate_throughput_strx.xclbin
cp -f ../vtd/runner/throughput/strx/profile_throughput_strx.json ../tools/bins/Runner/throughput/profile_throughput_strx.json
cp -f ../vtd/runner/throughput/strx/nop_throughput_strx.elf ../tools/bins/Runner/throughput/nop_throughput_strx.elf
cp -f ../vtd/runner/latency/phx/recipe_latency_phx.json ../tools/bins/Runner/latency/recipe_latency_phx.json
cp -f ../vtd/runner/latency/phx/validate_latency_phx.xclbin ../tools/bins/Runner/latency/validate_latency_phx.xclbin
cp -f ../vtd/runner/latency/phx/profile_latency_phx.json ../tools/bins/Runner/latency/profile_latency_phx.json
cp -f ../vtd/runner/latency/strx/recipe_latency_strx.json ../tools/bins/Runner/latency/recipe_latency_strx.json
cp -f ../vtd/runner/latency/strx/validate_latency_strx.xclbin ../tools/bins/Runner/latency/validate_latency_strx.xclbin
cp -f ../vtd/runner/latency/strx/profile_latency_strx.json ../tools/bins/Runner/latency/profile_latency_strx.json
cp -f ../vtd/runner/latency/strx/nop_latency_strx.elf ../tools/bins/Runner/latency/nop_latency_strx.elf
cp -f ../vtd/runner/df_bandwidth/phx/recipe_df_bandwidth_phx.json ../tools/bins/Runner/df_bandwidth/recipe_df_bandwidth_phx.json
cp -f ../vtd/runner/df_bandwidth/phx/df_bw_phx.elf ../tools/bins/Runner/df_bandwidth/df_bw_phx.elf
cp -f ../vtd/runner/df_bandwidth/phx/profile_df_bandwidth_phx.json ../tools/bins/Runner/df_bandwidth/profile_df_bandwidth_phx.json
cp -f ../vtd/runner/df_bandwidth/phx/validate_df_bandwidth_phx.xclbin ../tools/bins/Runner/df_bandwidth/validate_df_bandwidth_phx.xclbin
cp -f ../vtd/runner/df_bandwidth/strx/recipe_df_bandwidth_strx.json ../tools/bins/Runner/df_bandwidth/recipe_df_bandwidth_strx.json
cp -f ../vtd/runner/df_bandwidth/strx/df_bw_strx.elf ../tools/bins/Runner/df_bandwidth/df_bw_strx.elf
cp -f ../vtd/runner/df_bandwidth/strx/profile_df_bandwidth_strx.json ../tools/bins/Runner/df_bandwidth/profile_df_bandwidth_strx.json
cp -f ../vtd/runner/df_bandwidth/strx/validate_df_bandwidth_strx.xclbin ../tools/bins/Runner/df_bandwidth/validate_df_bandwidth_strx.xclbin
cp -f ../vtd/runner/gemm/strx/recipe_gemm_strx.json ../tools/bins/Runner/gemm/recipe_gemm_strx.json
cp -f ../vtd/runner/gemm/strx/gemm_elf_strx.xclbin ../tools/bins/Runner/gemm/gemm_elf_strx.xclbin
cp -f ../vtd/runner/gemm/strx/profile_gemm_strx.json ../tools/bins/Runner/gemm/profile_gemm_strx.json
cp -f ../vtd/runner/gemm/strx/gemm_int8_strx.elf ../tools/bins/Runner/gemm/gemm_int8_strx.elf
cp -f ../vtd/runner/aie_reconfig_overhead/strx/recipe_aie_reconfig_strx.json ../tools/bins/Runner/aie_reconfig_overhead/recipe_aie_reconfig_strx.json
cp -f ../vtd/runner/aie_reconfig_overhead/strx/recipe_aie_reconfig_nop_strx.json ../tools/bins/Runner/aie_reconfig_overhead/recipe_aie_reconfig_nop_strx.json
cp -f ../vtd/runner/aie_reconfig_overhead/strx/aie_reconfig_strx.xclbin ../tools/bins/Runner/aie_reconfig_overhead/aie_reconfig_strx.xclbin
cp -f ../vtd/runner/aie_reconfig_overhead/strx/aie_reconfig_overhead_strx.elf ../tools/bins/Runner/aie_reconfig_overhead/aie_reconfig_overhead_strx.elf
cp -f ../vtd/runner/aie_reconfig_overhead/strx/profile_aie_reconfig_strx.json ../tools/bins/Runner/aie_reconfig_overhead/profile_aie_reconfig_strx.json
cp -f ../vtd/runner/cmd_chain_latency/strx/recipe_cmd_chain_latency_strx.json ../tools/bins/Runner/cmd_chain_latency/recipe_cmd_chain_latency_strx.json
cp -f ../vtd/runner/cmd_chain_latency/strx/cmd_chain_latency_strx.xclbin ../tools/bins/Runner/cmd_chain_latency/cmd_chain_latency_strx.xclbin
cp -f ../vtd/runner/cmd_chain_latency/strx/profile_cmd_chain_latency_strx.json ../tools/bins/Runner/cmd_chain_latency/profile_cmd_chain_latency_strx.json
cp -f ../vtd/runner/cmd_chain_latency/strx/nop_cmd_chain_latency_strx.elf ../tools/bins/Runner/cmd_chain_latency/nop_cmd_chain_latency_strx.elf
cp -f ../vtd/runner/cmd_chain_throughput/strx/recipe_cmd_chain_throughput_strx.json ../tools/bins/Runner/cmd_chain_throughput/recipe_cmd_chain_throughput_strx.json
cp -f ../vtd/runner/cmd_chain_throughput/strx/cmd_chain_throughput_strx.xclbin ../tools/bins/Runner/cmd_chain_throughput/cmd_chain_throughput_strx.xclbin
cp -f ../vtd/runner/cmd_chain_throughput/strx/profile_cmd_chain_throughput_strx.json ../tools/bins/Runner/cmd_chain_throughput/profile_cmd_chain_throughput_strx.json
cp -f ../vtd/runner/cmd_chain_throughput/strx/nop_cmd_chain_throughput_strx.elf ../tools/bins/Runner/cmd_chain_throughput/nop_cmd_chain_throughput_strx.elf
cp -f ../vtd/runner/tct_all_column/recipe_tct_all_column_phx.json ../tools/bins/Runner/tct_all_column/recipe_tct_all_column_phx.json
cp -f ../vtd/runner/tct_all_column/recipe_tct_all_column_strx.json ../tools/bins/Runner/tct_all_column/recipe_tct_all_column_strx.json
cp -f ../vtd/runner/tct_all_column/profile_tct_all_column_phx.json ../tools/bins/Runner/tct_all_column/profile_tct_all_column_phx.json
cp -f ../vtd/runner/tct_all_column/profile_tct_all_column_strx.json ../tools/bins/Runner/tct_all_column/profile_tct_all_column_strx.json
cp -f ../vtd/runner/tct_all_column/tct_all_col_phx.xclbin ../tools/bins/Runner/tct_all_column/tct_all_col_phx.xclbin
cp -f ../vtd/runner/tct_all_column/tct_all_col_strx.xclbin ../tools/bins/Runner/tct_all_column/tct_all_col_strx.xclbin
cp -f ../vtd/runner/tct_all_column/tct_4col.elf ../tools/bins/Runner/tct_all_column/tct_4col.elf
cp -f ../vtd/runner/tct_one_column/recipe_tct_one_column_phx.json ../tools/bins/Runner/tct_one_column/recipe_tct_one_column_phx.json
cp -f ../vtd/runner/tct_one_column/recipe_tct_one_column_strx.json ../tools/bins/Runner/tct_one_column/recipe_tct_one_column_strx.json
cp -f ../vtd/runner/tct_one_column/profile_tct_one_column_phx.json ../tools/bins/Runner/tct_one_column/profile_tct_one_column_phx.json
cp -f ../vtd/runner/tct_one_column/profile_tct_one_column_strx.json ../tools/bins/Runner/tct_one_column/profile_tct_one_column_strx.json
cp -f ../vtd/runner/tct_one_column/tct_one_col_phx.xclbin ../tools/bins/Runner/tct_one_column/tct_one_col_phx.xclbin
cp -f ../vtd/runner/tct_one_column/tct_one_col_strx.xclbin ../tools/bins/Runner/tct_one_column/tct_one_col_strx.xclbin
cp -f ../vtd/runner/tct_one_column/tct_1col.elf ../tools/bins/Runner/tct_one_column/tct_1col.elf

if [[ $release == 1 ]]; then
  do_build $RELEASE_BUILD_TYPE
fi

if [[ $debug == 1 ]]; then
  do_build $DEBUG_BUILD_TYPE
fi

if [[ $package == 1 ]]; then
  echo "Packaging is automatically done as part of build"
  exit 0
fi
