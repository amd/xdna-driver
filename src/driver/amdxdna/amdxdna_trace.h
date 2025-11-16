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
#define TRACE_SYSTEM amdxdna_trace
#define TRACE_INCLUDE_FILE amdxdna_trace

TRACE_EVENT(amdxdna_debug_point,
	    TP_PROTO(const char *name, u64 number, const char *str),

	    TP_ARGS(name, number, str),

	    TP_STRUCT__entry(__string(name, name)
			     __field(u64, number)
			     __string(str, str)),

#if KERNEL_VERSION(6, 10, 0) > LINUX_VERSION_CODE
	    TP_fast_assign(__assign_str(name, name);
			   __entry->number = number;
			   __assign_str(str, str);),
#else
	    TP_fast_assign(__assign_str(name);
			   __entry->number = number;
			   __assign_str(str);),
#endif

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

#if KERNEL_VERSION(6, 10, 0) > LINUX_VERSION_CODE
	    TP_fast_assign(__assign_str(name, name);
			   __assign_str(str, str);
#else
	    TP_fast_assign(__assign_str(name);
			   __assign_str(str);
#endif
			   __entry->fence_context = sched_job->s_fence->finished.context;
			   __entry->fence_seqno = sched_job->s_fence->finished.seqno;
			   __entry->seq = seq;
			   __entry->op = op;),

	    TP_printk("fence=(context:%llu, seqno:%lld), %s seq#:%lld %s, op=%d",
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

#if KERNEL_VERSION(6, 10, 0) > LINUX_VERSION_CODE
		    TP_fast_assign(__assign_str(name, name);
				   __entry->chann_id = chann_id;
				   __entry->opcode = opcode;
				   __entry->msg_id = msg_id;),
#else
		    TP_fast_assign(__assign_str(name);
				   __entry->chann_id = chann_id;
				   __entry->opcode = opcode;
				   __entry->msg_id = msg_id;),
#endif

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

#if KERNEL_VERSION(6, 10, 0) > LINUX_VERSION_CODE
		    TP_fast_assign(__assign_str(name, name);
				   __entry->irq = irq;),
#else
		    TP_fast_assign(__assign_str(name);
				   __entry->irq = irq;),
#endif

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

#endif /* !defined(_AMDXDNA_TRACE_EVENTS_H_) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#include <trace/define_trace.h>
