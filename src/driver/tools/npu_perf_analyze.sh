#!/usr/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024, Advanced Micro Devices, Inc.

perf_out_file="perf.converted.out"

usage()
{
	echo "$0 [entry_index_begin:entry_index_end] event1_pattern event2_pattern"
	echo "Calculate time from event1 to event2 within [entry_index_begin,entry_index_end)"
	echo "event pattern examples:"
	echo "    sdt_xrt:ioctl_exit: \(.+\) arg1=DRM_IOCTL_AMDXDNA_WAIT_CMD"
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

range_start=0
range_end=0
event1=""
event2=""
if [ "$#" -eq 2 ]; then
	event1=$1
	event2=$2
elif [ "$#" -eq 3 ]; then
	st=$(echo $1 | cut -d':' -f1)
	end=$(echo $1 | cut -d':' -f2)
	if [ "${st}" != "" ]; then
		range_start=$(("10#${st}"))
	fi
	if [ "${end}" != "" ]; then
		range_end=$(("10#${end}"))
	fi
	event1=$2
	event2=$3
else
	usage
	exit 1
fi

if [ ! -f ${perf_out_file} ]; then
	echo "${perf_out_file} is not found"
	exit 1
else
	echo "Parsing ${perf_out_file}..."
fi

event1_ts=($(read_timestamps "${event1}"))
event1_ts_num=${#event1_ts[@]}
echo "${event1_ts_num} events for: '${event1}'"

event2_ts=($(read_timestamps "${event2}"))
event2_ts_num=${#event2_ts[@]}
echo "${event2_ts_num} events for: '${event2}'"

# Sanity check collected data
if [ ${event1_ts_num} -eq 0 ]; then
	echo No events found for ${event1}
	exit 1
fi
if [ ${event2_ts_num} -eq 0 ]; then
	echo No events found for ${event2}
	exit 1
fi
# Find first event2 entry index which comes after first event1
event2_index_base=-1
for (( i=0; i<${event2_ts_num}; i++ )); do
	if ! [[ ${event2_ts[i]} -lt ${event1_ts[0]} ]]; then
		event2_index_base=${i}
		break
	fi
done
if [ ${event2_index_base} -eq -1 ]; then
	echo No ${event2} is after ${event1}
	exit 1
fi

# Caculate time difference between two events
diffs=()
for (( i=0; i<${event1_ts_num}; i++ )); do
	i2=$(( i+${event2_index_base} ))
	if ! [ ${i2} -lt ${event2_ts_num} ]; then
		break
	fi
	diffs+=( $((event2_ts[i2] - event1_ts[i])) )
done
#echo ${diffs[@]}


# Data mining within specified range

if [ ${range_end} -eq 0 ]; then
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
