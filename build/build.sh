#! /bin/bash -

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 AMD, Inc. All rights reserved.

set -euo pipefail

usage()
{
  cat << USAGE_END
Usage: build.sh [options]
Options:
  -help                    Display this help
  -clean                   Clean build directory
  -debug                   Debug build and generate .deb package
  -release                 Release build and generate .deb package
  -j <n>                   Compile parallel (default: num of CPUs)
  -nocmake                 Do not regenerate cmake files
  -install_prefix <path>   Set CMAKE_INSTALL_PREFIX to path
  -verbose                 Enable verbose build
  -hello_umq               Hello UMQ Memory Test
  -npu3a                   Use iommu bypass magic to FW on npu3a attach
  -dir                     Download directory if apply
  -nokmod                  Don't build or install the kernel module
  -novxdna                 Don't build vxdna library
  -vxdna_test              Build and run vxdna unit tests (-novxdna disable this option)
  -package_legacy_driver   Build package with legacy driver source code
  -package_upstream_driver Build package with upstream driver source code (default)
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

download_url()
{
  local output=$1
  local url=$2

  if command -v wget >/dev/null 2>&1; then
    wget -O "$output" "$url"
  elif command -v curl >/dev/null 2>&1; then
    curl -fL -o "$output" "$url"
  else
    echo "Neither wget nor curl is installed; cannot download $url" >&2
    return 1
  fi
}

sync_npufws()
{
  local firmware_dir=${DOWNLOAD_BINS_DIR}/firmware
  local whence_snapshot=${BUILD_DIR}/../tools/WHENCE
  local sync_script=${BUILD_DIR}/../tools/sync_from_whence.py
  local commit_file=${firmware_dir}/.whence_commit

  mkdir -p "${firmware_dir}"
  # Release branches pin firmware with a committed tools/WHENCE snapshot; main
  # has no snapshot and always fetches the latest amd-ipu-staging manifest.
  if [ -f "${whence_snapshot}" ]; then
    echo "Sync NPUFW from pinned snapshot ${whence_snapshot}"
    python3 "${sync_script}" firmware --whence "${whence_snapshot}" \
      --out "${firmware_dir}" --commit-file "${commit_file}"
  else
    echo "Sync NPUFW from latest amd-ipu-staging WHENCE"
    python3 "${sync_script}" firmware --ref amd-ipu-staging \
      --out "${firmware_dir}" --commit-file "${commit_file}"
  fi
}

sync_vtd_archives()
{
  local vtd_dir=${DOWNLOAD_BINS_DIR}/vtd_archives
  local whence_manifest=${BUILD_DIR}/../tools/WHENCE
  local sync_script=${BUILD_DIR}/../tools/sync_from_whence.py
  # Record the resolved VTD commit next to the firmware .whence_commit so the
  # build caches both hashes together for the packaging step.
  local commit_file=${DOWNLOAD_BINS_DIR}/firmware/.vtd_commit

  mkdir -p "${vtd_dir}" "$(dirname "${commit_file}")"

  # Release branches pin the VTD archives with a "# vtd-commit:" line in the
  # committed tools/WHENCE. main has no snapshot, so synthesize a minimal
  # manifest holding the default "Repo: VTD" File: list (and no pin), which
  # makes the sync resolve and fetch the latest Xilinx/VTD commit.
  local vtd_whence="${whence_manifest}"
  local tmp_whence=""
  if [ ! -f "${whence_manifest}" ]; then
    tmp_whence=$(mktemp)
    # Remove the temporary manifest even if the sync below fails under "set -e"
    # before the explicit cleanup at the end of the function runs.
    trap 'rm -f "${tmp_whence}"' EXIT
    cat > "${tmp_whence}" <<'EOF'
Repo: VTD - xrt-smi validation archives fetched from github.com/Xilinx/VTD

File: archive/strx/xrt_smi_strx.a
File: archive/phx/xrt_smi_phx.a
File: archive/npu3/xrt_smi_npu3.a
EOF
    vtd_whence="${tmp_whence}"
    echo "Sync VTD archives from latest Xilinx/VTD (no committed WHENCE snapshot)"
  else
    echo "Sync VTD archives from ${whence_manifest}"
  fi

  python3 "${sync_script}" vtd --whence "${vtd_whence}" \
    --out "${vtd_dir}" --commit-file "${commit_file}"

  if [ -n "${tmp_whence}" ]; then
    rm -f "${tmp_whence}"
    trap - EXIT
  fi
}

run_vxdna_tests_func()
{
  BUILD_TYPE=$1

  if [[ $build_vxdna == 0 ]]; then
    echo "WARNING: -vxdna_test requires vxdna enabled. Skipping tests."
    return
  fi

  if [ ! -d $BUILD_TYPE ]; then
    echo "Build directory $BUILD_TYPE not found. Skipping tests."
    return
  fi

  echo ""
  echo "========================================"
  echo "Running vxdna unit tests ($BUILD_TYPE)"
  echo "========================================"
  echo ""

  TEST_BINARY="$BUILD_TYPE/src/vxdna/tests/vaccel_tests"

  if [ ! -f "$TEST_BINARY" ]; then
    echo "WARNING: Test binary not found at $TEST_BINARY"
    echo "Make sure BUILD_VXDNA_TESTING was enabled during CMake configuration"
    return 1
  fi

  # Run tests
  if "$TEST_BINARY"; then
    echo ""
    echo "========================================"
    echo "vxdna unit tests PASSED"
    echo "========================================"
    echo ""
    return 0
  else
    RESULT=$?
    echo ""
    echo "========================================"
    echo "vxdna unit tests FAILED"
    echo "========================================"
    echo ""
    return $RESULT
  fi
}

do_build()
{
  BUILD_TYPE=$1
  build_targets $BUILD_TYPE
  if [[ $nocmake == 0 ]]; then
    # Firmware and VTD archives are packaging inputs, not compile inputs, so
    # they are fetched here on the packaging path only, after the compile. A
    # plain compile never downloads. No need to sync firmware if the driver
    # build is skipped.
    if [[ $skip_kmod == 0 ]]; then
      sync_npufws
    fi
    # Sync VTD archives
    sync_vtd_archives
    # Prepare xbutil validate related files for packaging
    mkdir -p "$XBUTIL_VALIDATE_BINS_DIR"
    cp -r ${BUILD_DIR}/../tools/bins/* $XBUTIL_VALIDATE_BINS_DIR
    package_targets $BUILD_TYPE
  fi

  # Run tests if requested
  if [[ $run_vxdna_tests == 1 ]]; then
    run_vxdna_tests_func $BUILD_TYPE
  fi
}

# Config variables
clean=0
distclean=0
debug=1
release=0
nocmake=0
verbose=
skip_kmod=0
build_vxdna=1
run_vxdna_tests=0
package_legacy_driver=0
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
    -npu3a)
      export XDNA_DRV_BLD_FLAGS="${XDNA_DRV_BLD_FLAGS:+$XDNA_DRV_BLD_FLAGS }AMDXDNA_NPU3A=1"
      ;;
    -verbose)
      verbose=VERBOSE=1
      ;;
    -nokmod)
      skip_kmod=1
      ;;
    -novxdna)
      build_vxdna=0
      ;;
    -vxdna_test)
      run_vxdna_tests=1
      ;;
    -package_legacy_driver)
      package_legacy_driver=1
      ;;
    -package_upstream_driver)
      package_legacy_driver=0
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
cmake_extra_flags+=" -DBUILD_VXDNA=$build_vxdna"
cmake_extra_flags+=" -DPACKAGE_LEGACY_DRIVER=$package_legacy_driver"
# Enable testing if -vxdna_test flag is provided
if [[ $run_vxdna_tests == 1 ]]; then
  cmake_extra_flags+=" -DBUILD_VXDNA_TESTING=ON"
fi

if [[ ! -z "$download_dir" ]]; then
  echo "Specified download directory is $download_dir"
  DOWNLOAD_BINS_DIR=$download_dir
fi

if [[ $clean == 1 ]]; then
  echo "Only clean the build directory, will not perform other options if apply"
  rm -rf $DEBUG_BUILD_TYPE $RELEASE_BUILD_TYPE
  if [[ $distclean == 1 ]]; then
    rm -rf ${DOWNLOAD_BINS_DIR}
  fi
  exit 0
fi

if [[ $release == 1 ]]; then
  do_build $RELEASE_BUILD_TYPE
fi

if [[ $debug == 1 ]]; then
  do_build $DEBUG_BUILD_TYPE
fi
