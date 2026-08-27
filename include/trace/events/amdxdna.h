/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2025, Advanced Micro Devices, Inc.
 */

#if !defined(_AMDXDNA_TRACE_EVENTS_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _AMDXDNA_TRACE_EVENTS_H_

#include <linux/stringify.h>
#include <linux/tracepoint.h>
#include <linux/version.h>

#include <drm/gpu_scheduler.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM amdxdna
#define TRACE_INCLUDE_FILE amdxdna

TRACE_EVENT(amdxdna_debug_point,
	    TP_PROTO(const char *name, u64 number, const char *str),

	    TP_ARGS(name, number, str),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u64, number)
			     __string(str, str)),

	    TP_fast_assign(__assign_str(name);
			   __entry->number = number;
			   __assign_str(str);),

	    TP_printk("%s:%llu %s", __get_str(name), __entry->number,
		      __get_str(str))
);

TRACE_EVENT(xdna_job,
	    TP_PROTO(struct drm_sched_job *sched_job, const char *name,
		     const char *str, u64 seq, u32 op),

	    TP_ARGS(sched_job, name, str, seq, op),

	    TP_STRUCT__entry(__string(name, name)
			     __string(str, str)
			     __field(u64, fence_context)
			     __field(u64, fence_seqno)
			     __field(u64, seq)
			     __field(u32, op)),

	    TP_fast_assign(__assign_str(name);
			   __assign_str(str);
			   __entry->fence_context = sched_job->s_fence->finished.context;
			   __entry->fence_seqno = sched_job->s_fence->finished.seqno;
			   __entry->seq = seq;
			   __entry->op = op;),

	    TP_printk("fence=(context:%llu, seqno:%llu), %s seq#:%llu %s, op=%u",
		      __entry->fence_context, __entry->fence_seqno,
		      __get_str(name), __entry->seq,
		      __get_str(str),
		      __entry->op)
);

DECLARE_EVENT_CLASS(xdna_mbox_msg,
		    TP_PROTO(char *name, u8 chann_id, u32 opcode, u32 msg_id),

		    TP_ARGS(name, chann_id, opcode, msg_id),

		    TP_STRUCT__entry(__string(name, name)
				     __field(u32, chann_id)
				     __field(u32, opcode)
				     __field(u32, msg_id)),

		    TP_fast_assign(__assign_str(name);
				   __entry->chann_id = chann_id;
				   __entry->opcode = opcode;
				   __entry->msg_id = msg_id;),

		    TP_printk("%s.%d id 0x%x opcode 0x%x", __get_str(name),
			      __entry->chann_id, __entry->msg_id, __entry->opcode)
);

DEFINE_EVENT(xdna_mbox_msg, mbox_set_tail,
	     TP_PROTO(char *name, u8 chann_id, u32 opcode, u32 id),
	     TP_ARGS(name, chann_id, opcode, id)
);

DEFINE_EVENT(xdna_mbox_msg, mbox_set_head,
	     TP_PROTO(char *name, u8 chann_id, u32 opcode, u32 id),
	     TP_ARGS(name, chann_id, opcode, id)
);

DECLARE_EVENT_CLASS(xdna_mbox_name_id,
		    TP_PROTO(char *name, int irq),

		    TP_ARGS(name, irq),

		    TP_STRUCT__entry(__string(name, name)
				     __field(int, irq)),

		    TP_fast_assign(__assign_str(name);
				   __entry->irq = irq;),

		    TP_printk("%s.%d", __get_str(name), __entry->irq)
);

DEFINE_EVENT(xdna_mbox_name_id, mbox_irq_handle,
	     TP_PROTO(char *name, int irq),
	     TP_ARGS(name, irq)
);

DEFINE_EVENT(xdna_mbox_name_id, uc_irq_handle,
	     TP_PROTO(char *name, int msix_index),
	     TP_ARGS(name, msix_index)
);

DEFINE_EVENT(xdna_mbox_name_id, mbox_rx_worker,
	     TP_PROTO(char *name, int irq),
	     TP_ARGS(name, irq)
);

DEFINE_EVENT(xdna_mbox_name_id, uc_wakeup,
	     TP_PROTO(char *name, int msix_index),
	     TP_ARGS(name, msix_index)
);

DEFINE_EVENT(xdna_mbox_name_id, mbox_poll_handle,
	     TP_PROTO(char *name, int irq),
	     TP_ARGS(name, irq)
);

/*
 * Structured, per-operation latency tracepoints.
 *
 * These replace the former generic __amdxdna_trace_point probe that the
 * xrt_profiling userspace test used to consume: a fixed message string
 * (e.g. XRT_PROFILING_TRACE_ENTER/EXIT/UPDATE_WRITE_INDEX/...) plus up to
 * three anonymous u64 arguments whose meaning depended on the call site.
 * That worked for a single fixed consumer, but the events couldn't be
 * selectively enabled/filtered per operation with standard ftrace/perf
 * tooling (e.g. `echo 1 > events/amdxdna/xdna_irq_enter/enable`), and their
 * anonymous fields weren't self-describing.
 *
 * The named, typed events below cover every call site the old probe had in
 * ve2_hwctx.c / ve2_mgmt.c (hwctx create/destroy, partition initialize, IRQ,
 * command submit/wait/complete, scheduler work, mgmt-scheduler kick, host
 * queue write/read index), following the same enter/done pairing style
 * already used by the reference xilinx-ai-engine driver (ai-engine-trace.h:
 * aie_partition_request/aie_partition_request_done,
 * aie2ps_interrupt_user_event1/_done, ...) which the VE2 backend sits on top
 * of. A consumer computes latency by diffing the trace timestamps of the
 * start/done pair sharing the same correlation key (hwctx_id, and seq where
 * applicable) - no in-kernel duration math is required, matching how ftrace/
 * trace-cmd/perf already report per-event timestamps.
 *
 * These are backend-agnostic (TRACE_SYSTEM amdxdna) so aie2/aie4 can adopt
 * them too; only the VE2 backend calls them today.
 */

DECLARE_EVENT_CLASS(xdna_partition_init,
		    TP_PROTO(const char *name, u32 hwctx_id, u32 start_col, u32 num_col),

		    TP_ARGS(name, hwctx_id, start_col, num_col),

		    TP_STRUCT__entry(__string(name, name)
				     __field(u32, hwctx_id)
				     __field(u32, start_col)
				     __field(u32, num_col)),

		    TP_fast_assign(__assign_str(name);
				   __entry->hwctx_id = hwctx_id;
				   __entry->start_col = start_col;
				   __entry->num_col = num_col;),

		    TP_printk("%s: hwctx=%u start_col=%u num_col=%u",
			      __get_str(name), __entry->hwctx_id, __entry->start_col,
			      __entry->num_col)
);

DEFINE_EVENT(xdna_partition_init, xdna_partition_init_start,
	     TP_PROTO(const char *name, u32 hwctx_id, u32 start_col, u32 num_col),
	     TP_ARGS(name, hwctx_id, start_col, num_col)
);

TRACE_EVENT(xdna_partition_init_done,
	    TP_PROTO(const char *name, u32 hwctx_id, u32 start_col, u32 num_col, int ret),

	    TP_ARGS(name, hwctx_id, start_col, num_col, ret),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u32, hwctx_id)
			     __field(u32, start_col)
			     __field(u32, num_col)
			     __field(int, ret)),

	    TP_fast_assign(__assign_str(name);
			   __entry->hwctx_id = hwctx_id;
			   __entry->start_col = start_col;
			   __entry->num_col = num_col;
			   __entry->ret = ret;),

	    TP_printk("%s: hwctx=%u start_col=%u num_col=%u ret=%d",
		      __get_str(name), __entry->hwctx_id, __entry->start_col,
		      __entry->num_col, __entry->ret)
);

DECLARE_EVENT_CLASS(xdna_sched_work,
		    TP_PROTO(const char *name, u32 hwctx_id, u32 start_col),

		    TP_ARGS(name, hwctx_id, start_col),

		    TP_STRUCT__entry(__string(name, name)
				     __field(u32, hwctx_id)
				     __field(u32, start_col)),

		    TP_fast_assign(__assign_str(name);
				   __entry->hwctx_id = hwctx_id;
				   __entry->start_col = start_col;),

		    TP_printk("%s: hwctx=%u start_col=%u",
			      __get_str(name), __entry->hwctx_id, __entry->start_col)
);

DEFINE_EVENT(xdna_sched_work, xdna_sched_work_start,
	     TP_PROTO(const char *name, u32 hwctx_id, u32 start_col),
	     TP_ARGS(name, hwctx_id, start_col)
);

DEFINE_EVENT(xdna_sched_work, xdna_sched_work_done,
	     TP_PROTO(const char *name, u32 hwctx_id, u32 start_col),
	     TP_ARGS(name, hwctx_id, start_col)
);

TRACE_EVENT(xdna_irq_enter,
	    TP_PROTO(const char *name, u32 partition_id, u32 hwctx_id),

	    TP_ARGS(name, partition_id, hwctx_id),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u32, partition_id)
			     __field(u32, hwctx_id)),

	    TP_fast_assign(__assign_str(name);
			   __entry->partition_id = partition_id;
			   __entry->hwctx_id = hwctx_id;),

	    TP_printk("%s: partition=0x%x hwctx=%u",
		      __get_str(name), __entry->partition_id, __entry->hwctx_id)
);

TRACE_EVENT(xdna_irq_exit,
	    TP_PROTO(const char *name, u32 partition_id, u32 hwctx_id, u64 read_index,
		     u64 write_index),

	    TP_ARGS(name, partition_id, hwctx_id, read_index, write_index),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u32, partition_id)
			     __field(u32, hwctx_id)
			     __field(u64, read_index)
			     __field(u64, write_index)),

	    TP_fast_assign(__assign_str(name);
			   __entry->partition_id = partition_id;
			   __entry->hwctx_id = hwctx_id;
			   __entry->read_index = read_index;
			   __entry->write_index = write_index;),

	    TP_printk("%s: partition=0x%x hwctx=%u read_index=%llu write_index=%llu",
		      __get_str(name), __entry->partition_id, __entry->hwctx_id,
		      __entry->read_index, __entry->write_index)
);

TRACE_EVENT(xdna_cmd_submit,
	    TP_PROTO(const char *name, u32 hwctx_id, u64 seq, u32 op),

	    TP_ARGS(name, hwctx_id, seq, op),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u32, hwctx_id)
			     __field(u64, seq)
			     __field(u32, op)),

	    TP_fast_assign(__assign_str(name);
			   __entry->hwctx_id = hwctx_id;
			   __entry->seq = seq;
			   __entry->op = op;),

	    TP_printk("%s: hwctx=%u seq=%llu op=%u",
		      __get_str(name), __entry->hwctx_id, __entry->seq, __entry->op)
);

TRACE_EVENT(xdna_cmd_complete,
	    TP_PROTO(const char *name, u32 hwctx_id, u64 seq, u32 state),

	    TP_ARGS(name, hwctx_id, seq, state),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u32, hwctx_id)
			     __field(u64, seq)
			     __field(u32, state)),

	    TP_fast_assign(__assign_str(name);
			   __entry->hwctx_id = hwctx_id;
			   __entry->seq = seq;
			   __entry->state = state;),

	    TP_printk("%s: hwctx=%u seq=%llu state=%u",
		      __get_str(name), __entry->hwctx_id, __entry->seq, __entry->state)
);

/*
 * hwctx create/destroy latency. hwctx->name is not assigned until after
 * hwctx_init() returns successfully (see amdxdna_drm_create_hwctx_ioctl()),
 * and may already be freed on some hwctx_init() failure cleanup paths, so
 * these two pairs key on hwctx_id alone rather than the __string(name, ...)
 * used by the other events above.
 */
DECLARE_EVENT_CLASS(xdna_hwctx_init,
		    TP_PROTO(u32 hwctx_id, u32 num_tiles),

		    TP_ARGS(hwctx_id, num_tiles),

		    TP_STRUCT__entry(__field(u32, hwctx_id)
				     __field(u32, num_tiles)),

		    TP_fast_assign(__entry->hwctx_id = hwctx_id;
				   __entry->num_tiles = num_tiles;),

		    TP_printk("hwctx=%u num_tiles=%u",
			      __entry->hwctx_id, __entry->num_tiles)
);

DEFINE_EVENT(xdna_hwctx_init, xdna_hwctx_init_start,
	     TP_PROTO(u32 hwctx_id, u32 num_tiles),
	     TP_ARGS(hwctx_id, num_tiles)
);

TRACE_EVENT(xdna_hwctx_init_done,
	    TP_PROTO(u32 hwctx_id, u32 start_col, int ret),

	    TP_ARGS(hwctx_id, start_col, ret),

	    TP_STRUCT__entry(__field(u32, hwctx_id)
			     __field(u32, start_col)
			     __field(int, ret)),

	    TP_fast_assign(__entry->hwctx_id = hwctx_id;
			   __entry->start_col = start_col;
			   __entry->ret = ret;),

	    TP_printk("hwctx=%u start_col=%u ret=%d",
		      __entry->hwctx_id, __entry->start_col, __entry->ret)
);

TRACE_EVENT(xdna_hwctx_fini_start,
	    TP_PROTO(u32 hwctx_id, u32 start_col),

	    TP_ARGS(hwctx_id, start_col),

	    TP_STRUCT__entry(__field(u32, hwctx_id)
			     __field(u32, start_col)),

	    TP_fast_assign(__entry->hwctx_id = hwctx_id;
			   __entry->start_col = start_col;),

	    TP_printk("hwctx=%u start_col=%u", __entry->hwctx_id, __entry->start_col)
);

TRACE_EVENT(xdna_hwctx_fini_done,
	    TP_PROTO(u32 hwctx_id, u32 submitted, u32 completed),

	    TP_ARGS(hwctx_id, submitted, completed),

	    TP_STRUCT__entry(__field(u32, hwctx_id)
			     __field(u32, submitted)
			     __field(u32, completed)),

	    TP_fast_assign(__entry->hwctx_id = hwctx_id;
			   __entry->submitted = submitted;
			   __entry->completed = completed;),

	    TP_printk("hwctx=%u submitted=%u completed=%u",
		      __entry->hwctx_id, __entry->submitted, __entry->completed)
);

/*
 * ve2_mgmt_schedule_cmd() latency: from a newly-submitted command handed to
 * the partition scheduler to it being enqueued/kicked off (context activated
 * or switch armed). Complements xdna_sched_work_start/_done, which covers
 * the deferred workqueue side of the same scheduler.
 */
DECLARE_EVENT_CLASS(xdna_mgmt_schedule_cmd,
		    TP_PROTO(const char *name, u32 hwctx_id, u32 start_col, u64 command_index),

		    TP_ARGS(name, hwctx_id, start_col, command_index),

		    TP_STRUCT__entry(__string(name, name)
				     __field(u32, hwctx_id)
				     __field(u32, start_col)
				     __field(u64, command_index)),

		    TP_fast_assign(__assign_str(name);
				   __entry->hwctx_id = hwctx_id;
				   __entry->start_col = start_col;
				   __entry->command_index = command_index;),

		    TP_printk("%s: hwctx=%u start_col=%u command_index=%llu",
			      __get_str(name), __entry->hwctx_id, __entry->start_col,
			      __entry->command_index)
);

DEFINE_EVENT(xdna_mgmt_schedule_cmd, xdna_mgmt_schedule_cmd_start,
	     TP_PROTO(const char *name, u32 hwctx_id, u32 start_col, u64 command_index),
	     TP_ARGS(name, hwctx_id, start_col, command_index)
);

TRACE_EVENT(xdna_mgmt_schedule_cmd_done,
	    TP_PROTO(const char *name, u32 hwctx_id, u32 start_col, u64 command_index, int ret),

	    TP_ARGS(name, hwctx_id, start_col, command_index, ret),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u32, hwctx_id)
			     __field(u32, start_col)
			     __field(u64, command_index)
			     __field(int, ret)),

	    TP_fast_assign(__assign_str(name);
			   __entry->hwctx_id = hwctx_id;
			   __entry->start_col = start_col;
			   __entry->command_index = command_index;
			   __entry->ret = ret;),

	    TP_printk("%s: hwctx=%u start_col=%u command_index=%llu ret=%d",
		      __get_str(name), __entry->hwctx_id, __entry->start_col,
		      __entry->command_index, __entry->ret)
);

/*
 * Host queue write_index (host -> CERT, command committed) / read_index
 * (CERT -> host, command consumed) crossing @seq. Diffing the timestamps of
 * an xdna_queue_write_index and the xdna_queue_read_index that first reports
 * read_index > that same seq gives firmware execution time for that command.
 */
TRACE_EVENT(xdna_queue_write_index,
	    TP_PROTO(const char *name, u32 hwctx_id, u64 seq, u64 write_index),

	    TP_ARGS(name, hwctx_id, seq, write_index),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u32, hwctx_id)
			     __field(u64, seq)
			     __field(u64, write_index)),

	    TP_fast_assign(__assign_str(name);
			   __entry->hwctx_id = hwctx_id;
			   __entry->seq = seq;
			   __entry->write_index = write_index;),

	    TP_printk("%s: hwctx=%u seq=%llu write_index=%llu",
		      __get_str(name), __entry->hwctx_id, __entry->seq, __entry->write_index)
);

TRACE_EVENT(xdna_queue_read_index,
	    TP_PROTO(const char *name, u32 hwctx_id, u64 seq, u64 read_index),

	    TP_ARGS(name, hwctx_id, seq, read_index),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u32, hwctx_id)
			     __field(u64, seq)
			     __field(u64, read_index)),

	    TP_fast_assign(__assign_str(name);
			   __entry->hwctx_id = hwctx_id;
			   __entry->seq = seq;
			   __entry->read_index = read_index;),

	    TP_printk("%s: hwctx=%u seq=%llu read_index=%llu",
		      __get_str(name), __entry->hwctx_id, __entry->seq, __entry->read_index)
);

/*
 * ve2_cmd_submit() function-entry marker. Diffing against xdna_cmd_submit
 * (same hwctx_id, emitted once the command is actually committed to the
 * host queue) gives the submit-path latency ("Submit" column).
 */
TRACE_EVENT(xdna_cmd_submit_start,
	    TP_PROTO(const char *name, u32 hwctx_id, u32 start_col),

	    TP_ARGS(name, hwctx_id, start_col),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u32, hwctx_id)
			     __field(u32, start_col)),

	    TP_fast_assign(__assign_str(name);
			   __entry->hwctx_id = hwctx_id;
			   __entry->start_col = start_col;),

	    TP_printk("%s: hwctx=%u start_col=%u",
		      __get_str(name), __entry->hwctx_id, __entry->start_col)
);

/*
 * ve2_cmd_wait() latency: from a waiter blocking on a command's completion
 * to it observing (or giving up on) that completion. @ret mirrors the
 * function's return value (e.g. -ERESTARTSYS if interrupted by a signal).
 */
TRACE_EVENT(xdna_cmd_wait_start,
	    TP_PROTO(const char *name, u32 hwctx_id, u64 seq),

	    TP_ARGS(name, hwctx_id, seq),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u32, hwctx_id)
			     __field(u64, seq)),

	    TP_fast_assign(__assign_str(name);
			   __entry->hwctx_id = hwctx_id;
			   __entry->seq = seq;),

	    TP_printk("%s: hwctx=%u seq=%llu",
		      __get_str(name), __entry->hwctx_id, __entry->seq)
);

TRACE_EVENT(xdna_cmd_wait_done,
	    TP_PROTO(const char *name, u32 hwctx_id, u64 seq, int ret),

	    TP_ARGS(name, hwctx_id, seq, ret),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u32, hwctx_id)
			     __field(u64, seq)
			     __field(int, ret)),

	    TP_fast_assign(__assign_str(name);
			   __entry->hwctx_id = hwctx_id;
			   __entry->seq = seq;
			   __entry->ret = ret;),

	    TP_printk("%s: hwctx=%u seq=%llu ret=%d",
		      __get_str(name), __entry->hwctx_id, __entry->seq, __entry->ret)
);

TRACE_EVENT(xdna_job_queue,
	    TP_PROTO(const char *name, u64 seq, u64 outstanding, const char *str),

	    TP_ARGS(name, seq, outstanding, str),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u64, seq)
			     __field(u64, outstanding)
			     __string(str, str)),

	    TP_fast_assign(__assign_str(name);
			   __entry->seq = seq;
			   __entry->outstanding = outstanding;
			   __assign_str(str);),

	    TP_printk("%s seq#:%llu outstanding:%llu %s", __get_str(name),
		      __entry->seq, __entry->outstanding, __get_str(str))
);

#endif /* !defined(_AMDXDNA_TRACE_EVENTS_H_) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#include <trace/define_trace.h>
