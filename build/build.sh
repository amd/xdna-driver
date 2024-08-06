#! /bin/bash -

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024, Advanced Micro Devices, Inc.
#

set -euo pipefail

usage()
{
	cat << USAGE_END
Usage: build.sh [options]
Options:
	-help										Display this help
	-clean									Clean build directory
	-debug									Only debug build
	-release								release build
	-example								example build
	-package								Generate xrt_plugin .deb package
	-j <n>									Compile parallel (default: num of CPUs)
	-nocmake								Do not regenerate cmake files
	-install_prefix <path>	Set CMAKE_INSTALL_PREFIX to path"
	-verbose								Enable verbose build
	-hello_umq              Hello UMQ Memory Test
	-dir	      						Download directory if apply
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

# Config variables
clean=0
distclean=0
debug=1
release=0
package=0
example=0
nocmake=0
verbose=
njobs=`grep -c ^processor /proc/cpuinfo`
download_dir=
xrt_install_prefix="/opt/xilinx"
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

cmake_extra_flags+=" -DCMAKE_INSTALL_PREFIX=$xrt_install_prefix -DXRT_INSTALL_PREFIX=$xrt_install_prefix"

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

if [[ $package == 1 ]]; then
	download_npufws
  # Prepare xbutil validate related files for packaging
	mkdir -p $XBUTIL_VALIDATE_BINS_DIR
  cp -r ../tools/bins/* $XBUTIL_VALIDATE_BINS_DIR
	package_targets $DEBUG_BUILD_TYPE
	package_targets $RELEASE_BUILD_TYPE
	exit 0
fi

if [[ $release == 1 ]]; then
	build_targets $RELEASE_BUILD_TYPE
fi

if [[ $debug == 1 ]]; then
	build_targets $DEBUG_BUILD_TYPE
fi

# vim: ts=2 sw=2
