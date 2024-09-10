#!/usr/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024, Advanced Micro Devices, Inc.

usage()
{
  cat << USAGE_END
Usage: $0 [options] event1_pattern event2_pattern
Options:
  -file/-f: Trace log file for parsing
  -range/-r: [entry_index_begin:entry_index_end), e.g.: 100:200
Parsing trace log file to find time interval from event1 to event2.
event pattern examples:
  "sdt_xrt:ioctl_exit: \(.+\) arg1=DRM_IOCTL_AMDXDNA_WAIT_CMD"
USAGE_END
}

read_timestamps()
{
	timestamps=()

	while IFS= read -r line; do
		if [ "$line" != "" ]; then
			timestamps+=($(("10#${line}")))
		fi
	done <<< `egrep "$1" ${perf_out_file} | awk '{print $4}' | tr -d '.' | tr -d ':'`
	echo ${timestamps[@]}
}

if [ "$#" -eq 0 ]; then
	usage
	exit 1
fi

range_start=-1
range_end=-1
event1=""
event2=""
perf_out_file="perf.converted.out"
while [ $# -gt 0 ]; do
	case "$1" in
		-range | -r)
			st=$(echo $2 | cut -d':' -f1)
			end=$(echo $2 | cut -d':' -f2)
			if [ "${st}" != "" ]; then
				if [[ "${st}" =~ ^[0-9]+$ ]]; then
					range_start=$(("10#${st}"))
				else
					echo Invalid range start: ${st}
					exit 1
				fi
			fi
			if [ "${end}" != "" ]; then
				if [[ "${end}" =~ ^[0-9]+$ ]]; then
					range_end=$(("10#${end}"))
				else
					echo Invalid range end: ${end}
					exit 1
				fi
			fi
			shift
			;;
		-file | -f)
			perf_out_file=$2
			shift
			;;
		*)
			break
			;;
	esac
	shift
done
event1=$1
event2=$2

if [ ! -f ${perf_out_file} ]; then
	echo "${perf_out_file} is not found"
	exit 1
else
	echo "Parsing ${perf_out_file}..."
fi

event1_ts=($(read_timestamps "${event1}"))
event1_ts_num=${#event1_ts[@]}
if [ ${event1_ts_num} -eq 0 ]; then
	echo No events found for ${event1}
	exit 1
fi
echo "${event1_ts_num} events for: '${event1}'"

event2_ts=($(read_timestamps "${event2}"))
event2_ts_num=${#event2_ts[@]}
if [ ${event2_ts_num} -eq 0 ]; then
	echo No events found for ${event2}
	exit 1
fi
echo "${event2_ts_num} events for: '${event2}'"

# Caculate time difference between two events
diffs=()
i1=0
i2=0
while [ ${i1} -lt ${event1_ts_num} ]; do
	while [[ ${i2} -lt ${event2_ts_num} && ${event2_ts[i2]} -lt ${event1_ts[i1]} ]]; do
		(( i2++ ))
	done
	if [ ${i2} -eq ${event2_ts_num} ]; then
		break
	fi
	diffs+=( $((event2_ts[i2] - event1_ts[i1])) )
	(( i1++ ))
	(( i2++ ))
done
#echo ${diffs[@]}


# Data mining within specified range

if [ ${range_start} -eq -1 ]; then
	range_start=0
fi
if [ ${range_end} -eq -1 ]; then
	range_end=${#diffs[@]}
fi
if [ ${range_end} -eq ${range_start} ]; then
	echo Range start and end are the same
	exit 1
elif [ ${range_end} -lt ${range_start} ]; then
	echo Range start after end
	exit 1
fi

total=0
largest=${diffs[${range_start}]}
largest_idx=${range_start}
smallest=${diffs[${range_start}]}
smallest_idx=${range_start}
for (( i=${range_start}; i<${range_end}; i++ )); do
	total=$(( total + diffs[i] ))
	if [[ ${largest} -lt ${diffs[i]} ]]; then
		largest=${diffs[i]}
		largest_idx=${i}
	fi
	if [[ ${smallest} -gt ${diffs[i]} ]]; then
		smallest=${diffs[i]}
		smallest_idx=${i}
	fi
done

# Output result
total_events=$(( range_end - range_start ))
echo Average over ${total_events} events: $(( total / total_events ))us
echo Largest:  ${largest}us@${largest_idx}
echo Smallest: ${smallest}us@${smallest_idx}
