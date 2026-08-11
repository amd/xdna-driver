#!/usr/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024, Advanced Micro Devices, Inc.

usage()
{
  cat << USAGE_END
Usage: $0 [options] event1_pattern event2_pattern
Options:
  -help/-h: Show this help and exit
  -file/-f: Trace log file for parsing
  -range/-r: [entry_index_begin:entry_index_end), e.g.: 100:200
  -key/-k: Only consider lines also matching this pattern, e.g.: "hwctx=3" or "seq=42".
           Use this to correlate paired events (e.g. xdna_cmd_submit/xdna_cmd_complete,
           xdna_partition_init_start/_done) by hwctx_id or seq instead of just nearest
           timestamp, which can mis-pair events when multiple hw contexts are interleaved
           (e.g. VE2 with several hwctx sharing a partition).
Parsing trace log file to find time interval from event1 to event2.
event pattern examples:
  "sdt_xrt:ioctl_exit: \(.+\) arg1=DRM_IOCTL_AMDXDNA_WAIT_CMD"
  -k "hwctx=3" "amdxdna:xdna_partition_init_start" "amdxdna:xdna_partition_init_done"
  -k "seq=42" "amdxdna:xdna_cmd_submit" "amdxdna:xdna_cmd_complete"
USAGE_END
}

read_timestamps()
{
	timestamps=()

	local matched
	matched=$(egrep "$1" ${perf_out_file})
	if [ -n "${key_filter}" ]; then
		matched=$(echo "${matched}" | egrep "${key_filter}")
	fi

	while IFS= read -r line; do
		if [ "$line" != "" ]; then
			timestamps+=($(("10#${line}")))
		fi
	done <<< `echo "${matched}" | awk '{print $4}' | tr -d '.' | tr -d ':'`
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
key_filter=""
perf_out_file="perf.converted.out"
while [ $# -gt 0 ]; do
	case "$1" in
		-h | --help)
			usage
			exit 0
			;;
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
		-key | -k)
			key_filter=$2
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
if [ -n "${key_filter}" ]; then
	echo "Filtering by key: '${key_filter}'"
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

# Calculate time difference between two events. Pair each event2 occurrence
# with the closest preceding, not-yet-used event1 occurrence; skip any event2
# that happens before the first event1. Stop once either array is exhausted.
diffs_event1=()
diffs_event2=()
diffs=()
i1=0
i2=0
while [[ ${i1} -lt ${event1_ts_num} && ${i2} -lt ${event2_ts_num} ]]; do
	if [[ ${event2_ts[i2]} -lt ${event1_ts[i1]} ]]; then
		(( i2++ ))
		continue
	fi

	while [[ $(( i1 + 1 )) -lt ${event1_ts_num} && ${event1_ts[i1+1]} -lt ${event2_ts[i2]} ]]; do
		(( i1++ ))
	done

	diffs_event1+=( $((event1_ts[i1])) )
	diffs_event2+=( $((event2_ts[i2])) )
	diffs+=( $((event2_ts[i2] - event1_ts[i1])) )
	(( i1++ ))
	(( i2++ ))
done
#echo ${event1_ts[@]} > /tmp/e1
#echo ${event2_ts[@]} > /tmp/e2
#echo ${diffs[@]} > /tmp/diffs


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
echo Average over ${total_events} events: $(( total / total_events ))ns
echo Largest:  ${largest}ns@${largest_idx}: event1=${diffs_event1[largest_idx]}, event2=${diffs_event2[largest_idx]}
echo Smallest: ${smallest}ns@${smallest_idx}: event1=${diffs_event1[smallest_idx]}, event2=${diffs_event2[smallest_idx]}
