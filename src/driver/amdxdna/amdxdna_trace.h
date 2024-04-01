/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024, Advanced Micro Devices, Inc.
 */

#if !defined(_AMDXDNA_TRACE_EVENTS_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _AMDXDNA_TRACE_EVENTS_H_

#include <linux/stringify.h>
#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM amdxdna_trace
#define TRACE_INCLUDE_FILE amdxdna_trace

TRACE_EVENT(amdxdna_debug_point,
	    TP_PROTO(const char *name, int line, const char *str),

	    TP_ARGS(name, line, str),

	    TP_STRUCT__entry(__string(name, name)
			     __field(int, line)
			     __string(str, str)),

	    TP_fast_assign(__assign_str(name, name);
			   __entry->line = line;
			   __assign_str(str, str);),

	    TP_printk("%s:%d %s", __get_str(name), __entry->line,
		      __get_str(str))
);

TRACE_EVENT(xdna_job,
	    TP_PROTO(const char *name, const char *str, u64 seq),

	    TP_ARGS(name, str, seq),

	    TP_STRUCT__entry(__string(name, name)
			     __string(str, str)
			     __field(u64, seq)),

	    TP_fast_assign(__assign_str(name, name);
			   __assign_str(str, str);
			   __entry->seq = seq;),

	    TP_printk("%s seq#:%lld %s", __get_str(name), __entry->seq,
		      __get_str(str))
);

DECLARE_EVENT_CLASS(xdna_mbox_msg,
		    TP_PROTO(char *name, u8 chann_id, u32 opcode, u32 msg_id),

		    TP_ARGS(name, chann_id, opcode, msg_id),

		    TP_STRUCT__entry(__string(name, name)
				     __field(u32, chann_id)
				     __field(u32, opcode)
				     __field(u32, msg_id)),

		    TP_fast_assign(__assign_str(name, name);
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

TRACE_EVENT(mbox_irq_handle,
	    TP_PROTO(char *name, int irq),

	    TP_ARGS(name, irq),

	    TP_STRUCT__entry(__string(name, name)
			     __field(int, irq)),

	    TP_fast_assign(__assign_str(name, name);
			   __entry->irq = irq;),

	    TP_printk("%s.%d", __get_str(name), __entry->irq)
);

#endif /* !defined(_AMDXDNA_TRACE_EVENTS_H_) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#include <trace/define_trace.h>
