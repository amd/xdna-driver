#! /bin/bash --

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024, Advanced Micro Devices, Inc.

set -eu

bold=$(tput bold)
normal=$(tput sgr0)
red=$(tput setaf 1)
yellow=$(tput setaf 3)
blue=$(tput setaf 4)

trace_info()
{
	what=$1
	echo -e "[INFO]: $what"
}

trace_warn()
{
	what=$1
	echo -e "[${yellow}WARNING${normal}]: $what"
}

trace_error()
{
	what=$1
	echo -e "[${red}ERROR${normal}]: $what" 1>&2
	exit 1
}

add_sdt_xrt()
{
	perf list | grep sdt_xrt > /dev/null && sdt_pre_enabled=1
	if [[ $sdt_pre_enabled == 1 ]]; then
		remove_sdt_xrt
		#trace_warn "XRT SDT had beed added. Skip..."
		#return
	fi

	# Add XRT SDT events
	perf buildid-cache --add $xrt_libs
	# Convert SDT events to trace points
	perf probe --add=sdt_xrt:* &> /dev/null

	trace_info "XRT SDT is added"
}

remove_sdt_xrt()
{
	#if [[ $sdt_pre_enabled == 1 ]]; then
	#	trace_warn "XRT SDT was pre added. Skip..."
	#	return
	#fi

	# Delete SDT trace points
	perf probe --del=sdt_xrt:* &> /dev/null
	# Remove XRT STD events
	perf buildid-cache --remove $xrt_libs
	trace_info "XRT SDT is removed"
}

## -------- trace flow start --------
if [ "$EUID" -ne 0 ]; then
	trace_error "Please run as root"
fi

# Global variables
sdt_pre_enabled=0
xrt_lib_prefix="/opt/xilinx/xrt/lib"
accel_debugfs="/sys/kernel/debug/accel"
xrt_libs="${xrt_lib_prefix}/libxrt_coreutil.so,${xrt_lib_prefix}/libxrt_driver_xdna.so"
perf_record_args="-e amdxdna_trace:* "
perf_record_args+="-e sdt_xrt:* "
exec_cmd=""

perf --version > /dev/null

# Argument parsing
exec_cmd=$@
if [[ -z "$exec_cmd" ]]; then
	trace_error "Please put execute application at the end"
fi

dev=""
ioctl_sed_expr=""
for dir in $(ls $accel_debugfs); do
	accel_fs_name=$(cat ${accel_debugfs}/$dir/name)
	driver_name=$(echo $accel_fs_name | awk '{print $1}')
	if [[ ! "$driver_name" =~ "amdxdna" ]]; then
		continue
	fi

	if [[ ! -f ${accel_debugfs}/$dir/ioctl_id ]]; then
		trace_error "${accel_debugfs}/$dir/ioctl_id not exist. amdxdna driver too old?"
	fi

	dev=$(echo $accel_fs_name | awk -F'[ =]' '{print $3}')
	ioctl_sed_expr=$(awk -F ':' '{print "s/"$1"/"$2"/g"}' ${accel_debugfs}/$dir/ioctl_id)
done

if [[ -z "$dev" ]]; then
	trace_error "No device found"
fi

trace_info "Found NPU device $dev at ${accel_debugfs}"

add_sdt_xrt

command="perf record $perf_record_args -a $exec_cmd"
trace_info "$command"
eval $command

tmp_file=/tmp/perf.out
# convert timestamp from second to microsecond to avoid floating numbers
#perf script | awk '{ $4=$4*1000000; print }' > ${tmp_file}
perf script --reltime > ${tmp_file}
# replace IOCTL cmd number to name
sed "$ioctl_sed_expr" "${tmp_file}" > perf.converted.out
rm -rf ${tmp_file}

remove_sdt_xrt
## -------- trace flow end --------
