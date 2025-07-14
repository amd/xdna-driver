// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022-2025, Advanced Micro Devices, Inc.
 */

#include <linux/bitfield.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/build_bug.h>
#include <linux/interrupt.h>
#include <linux/dev_printk.h>
#if defined(CONFIG_DEBUG_FS)
#include <linux/seq_file.h>
#include <linux/wait.h>
#endif
#ifdef AMDXDNA_DEVEL
#include <linux/kthread.h>
#endif
#include <linux/irqreturn.h>
#include "amdxdna_trace.h"
#include "amdxdna_mailbox.h"

#define MB_ERR(chann, fmt, args...) \
({ \
	typeof(chann) _chann = chann; \
	dev_err((_chann)->mb->dev, "xdna_mailbox.%d: "fmt, \
		(_chann)->msix_irq, ##args); \
})
#define MB_DBG(chann, fmt, args...) \
({ \
	typeof(chann) _chann = chann; \
	dev_dbg((_chann)->mb->dev, "xdna_mailbox.%d: "fmt, \
		(_chann)->msix_irq, ##args); \
})
#define MB_WARN_ONCE(chann, fmt, args...) \
({ \
	typeof(chann) _chann = chann; \
	dev_warn_once((_chann)->mb->dev, "xdna_mailbox.%d: "fmt, \
		      (_chann)->msix_irq, ##args); \
})

#define MAGIC_VAL			0x1D000000U
#define MAGIC_VAL_MASK			0xFF000000
#define MAX_MSG_ID_ENTRIES		256
#define MAILBOX_NAME			"xdna_mailbox"
#define MSG_ID2ENTRY(msg_id)		((msg_id) & ~MAGIC_VAL_MASK)

#ifdef AMDXDNA_DEVEL
int mailbox_polling;
module_param(mailbox_polling, int, 0444);
MODULE_PARM_DESC(mailbox_polling, "<=0:interrupt(default); >0:poll interval in ms; <0: busy poll");
#define MB_DEFAULT_NO_POLL (mailbox_polling <= 0)
#define MB_PERIODIC_POLL   (mailbox_polling > 0)
#define MB_FORCE_USER_POLL   (mailbox_polling < 0)

#define MB_TIMER_JIFF msecs_to_jiffies(mailbox_polling)
#endif

enum channel_res_type {
	CHAN_RES_X2I,
	CHAN_RES_I2X,
	CHAN_RES_NUM
};

struct mailbox {
	struct device		*dev;
	struct xdna_mailbox_res	res;
	spinlock_t		mbox_lock; /* protect channel list */
	struct list_head        chann_list;
	struct list_head        poll_chann_list;
	struct task_struct	*polld;
	struct wait_queue_head	poll_wait;
	bool			sent_msg; /* For polld */
#if defined(CONFIG_DEBUG_FS)
	struct list_head        res_records;
#endif /* CONFIG_DEBUG_FS */
};

#if defined(CONFIG_DEBUG_FS)
struct mailbox_res_record {
	enum xdna_mailbox_channel_type	type;
	struct list_head		re_entry;
	struct xdna_mailbox_chann_res	re_x2i;
	struct xdna_mailbox_chann_res	re_i2x;
	int				re_irq;
	int				active;
};
#endif /* CONFIG_DEBUG_FS */

struct mailbox_channel {
	struct mailbox			*mb;
#if defined(CONFIG_DEBUG_FS)
	struct mailbox_res_record	*record;
#endif
	struct list_head		chann_entry;
	struct xdna_mailbox_chann_res	res[CHAN_RES_NUM];
	int				msix_irq;
	u32				x2i_tail;
	u32				iohub_int_addr;
	enum xdna_mailbox_channel_type	type;
	struct xarray			chan_xa;
	u32				next_msgid;

	/* Received msg related fields */
	struct workqueue_struct		*work_q;
	struct work_struct		rx_work;
	u32				i2x_head;
	bool				bad_state;
	u32				last_msg_id;

#ifdef AMDXDNA_DEVEL
	struct timer_list		timer;
#endif
};

#define MSG_BODY_SZ		GENMASK(10, 0)
#define MSG_PROTO_VER		GENMASK(23, 16)
struct xdna_msg_header {
	__u32 total_size;
	__u32 sz_ver;
	__u32 id;
	__u32 opcode;
} __packed;

static_assert(sizeof(struct xdna_msg_header) == 16);

struct mailbox_pkg {
	struct xdna_msg_header	header;
	__u32			payload[];
};

/* The protocol version. */
#define MSG_PROTOCOL_VERSION	0x1
/* The tombstone value. */
#define TOMBSTONE		0xDEADFACE

struct mailbox_msg {
	void			*handle;
	int			(*notify_cb)(void *handle, void __iomem *data, size_t size);
	size_t			pkg_size; /* package size in bytes */
	struct mailbox_pkg	pkg;
};

static void mailbox_reg_write(struct mailbox_channel *mb_chann, u32 mbox_reg, u32 data)
{
	struct xdna_mailbox_res *mb_res = &mb_chann->mb->res;
	void __iomem *ringbuf_addr = mb_res->mbox_base + mbox_reg;

	writel(data, ringbuf_addr);
}

static u32 mailbox_reg_read(struct mailbox_channel *mb_chann, u32 mbox_reg)
{
	struct xdna_mailbox_res *mb_res = &mb_chann->mb->res;
	void __iomem *ringbuf_addr = mb_res->mbox_base + mbox_reg;

	return readl(ringbuf_addr);
}

static inline void mailbox_irq_acknowledge(struct mailbox_channel *mb_chann)
{
	if (!mb_chann->iohub_int_addr)
		return;

	mailbox_reg_write(mb_chann, mb_chann->iohub_int_addr, 0);
}

static inline u32 mailbox_irq_status(struct mailbox_channel *mb_chann)
{
	if (!mb_chann->iohub_int_addr)
		return 0;

	return mailbox_reg_read(mb_chann, mb_chann->iohub_int_addr);
}

static inline void
mailbox_set_headptr(struct mailbox_channel *mb_chann, u32 headptr_val)
{
	mailbox_reg_write(mb_chann, mb_chann->res[CHAN_RES_I2X].mb_head_ptr_reg, headptr_val);
	mb_chann->i2x_head = headptr_val;
}

static inline void
mailbox_set_tailptr(struct mailbox_channel *mb_chann, u32 tailptr_val)
{
	mailbox_reg_write(mb_chann, mb_chann->res[CHAN_RES_X2I].mb_tail_ptr_reg, tailptr_val);
	mb_chann->x2i_tail = tailptr_val;
}

static inline u32
mailbox_get_headptr(struct mailbox_channel *mb_chann, enum channel_res_type type)
{
	return mailbox_reg_read(mb_chann, mb_chann->res[type].mb_head_ptr_reg);
}

static inline u32
mailbox_get_tailptr(struct mailbox_channel *mb_chann, enum channel_res_type type)
{
	return mailbox_reg_read(mb_chann, mb_chann->res[type].mb_tail_ptr_reg);
}

static inline u32
mailbox_get_ringbuf_size(struct mailbox_channel *mb_chann, enum channel_res_type type)
{
	return mb_chann->res[type].rb_size;
}

static inline int mailbox_validate_msgid(struct mailbox_channel *mb_chann, u32 msg_id)
{
	u32 exp_id = mb_chann->last_msg_id + 1;

	if ((msg_id & MAGIC_VAL_MASK) != MAGIC_VAL) {
		MB_ERR(mb_chann, "Bad message ID 0x%x", msg_id);
		return false;
	}

	if (mb_chann->type == MB_CHANNEL_MGMT)
		return true;

	if (MSG_ID2ENTRY(msg_id) && msg_id != exp_id) {
		MB_ERR(mb_chann, "Non-contiguous message ID 0x%x, expecting 0x%x",
		       msg_id, exp_id);
		return false;
	}
	return true;
}

static int mailbox_acquire_msgid(struct mailbox_channel *mb_chann, struct mailbox_msg *mb_msg)
{
	u32 msg_id;
	int ret;

	ret = xa_alloc_cyclic_irq(&mb_chann->chan_xa, &msg_id, mb_msg,
				  XA_LIMIT(0, MAX_MSG_ID_ENTRIES - 1),
				  &mb_chann->next_msgid, GFP_NOWAIT);
	if (ret < 0)
		return ret;

	/*
	 * Add MAGIC_VAL to the higher bits.
	 */
	msg_id |= MAGIC_VAL;
	return msg_id;
}

static bool mailbox_channel_no_msg(struct mailbox_channel *mb_chann)
{
	return xa_empty(&mb_chann->chan_xa);
}

static void mailbox_release_msgid(struct mailbox_channel *mb_chann, int msg_id)
{
	msg_id = MSG_ID2ENTRY(msg_id);
	xa_erase_irq(&mb_chann->chan_xa, msg_id);
}

static void mailbox_release_msg(struct mailbox_channel *mb_chann,
				struct mailbox_msg *mb_msg)
{
	MB_DBG(mb_chann, "msg_id 0x%x msg opcode 0x%x",
	       mb_msg->pkg.header.id, mb_msg->pkg.header.opcode);
	mb_msg->notify_cb(mb_msg->handle, NULL, 0);
	kfree(mb_msg);
}

static int
mailbox_send_msg(struct mailbox_channel *mb_chann, struct mailbox_msg *mb_msg)
{
	void __iomem *write_addr;
	u32 ringbuf_size;
	u32 head, tail;
	u32 start_addr;
	u32 tmp_tail;

	head = mailbox_get_headptr(mb_chann, CHAN_RES_X2I);
	tail = mb_chann->x2i_tail;
	ringbuf_size = mailbox_get_ringbuf_size(mb_chann, CHAN_RES_X2I);
	start_addr = mb_chann->res[CHAN_RES_X2I].rb_start_addr;
	tmp_tail = tail + mb_msg->pkg_size;

	if (tail < head && tmp_tail >= head) {
		MB_DBG(mb_chann, "head 0x%x tail 0x%x tmp_tail 0x%x",
		       head, tail, tmp_tail);
		goto no_space;
	}

	if (tail >= head && (tmp_tail > ringbuf_size - sizeof(u32) &&
			     mb_msg->pkg_size >= head)) {
		MB_DBG(mb_chann, "head 0x%x tail 0x%x tmp_tail 0x%x",
		       head, tail, tmp_tail);
		goto no_space;
	}

	if (tail >= head && tmp_tail > ringbuf_size - sizeof(u32)) {
		write_addr = mb_chann->mb->res.ringbuf_base + start_addr + tail;
		writel(TOMBSTONE, write_addr);

		/* tombstone is set. Write from the start of the ringbuf */
		tail = 0;
	}

	write_addr = mb_chann->mb->res.ringbuf_base + start_addr + tail;
	memcpy_toio(write_addr, &mb_msg->pkg, mb_msg->pkg_size);
	mailbox_set_tailptr(mb_chann, tail + mb_msg->pkg_size);

	trace_mbox_set_tail(MAILBOX_NAME, mb_chann->msix_irq,
			    mb_msg->pkg.header.opcode,
			    mb_msg->pkg.header.id);

	return 0;

no_space:
	return -ENOSPC;
}

static int
mailbox_get_resp(struct mailbox_channel *mb_chann, struct xdna_msg_header *header,
		 void __iomem *data)
{
	struct mailbox_msg *mb_msg;
	int msg_id;
	int ret;

	msg_id = header->id;
	if (!mailbox_validate_msgid(mb_chann, msg_id))
		return -EINVAL;
	mb_chann->last_msg_id = msg_id;

	msg_id = MSG_ID2ENTRY(msg_id);
	mb_msg = xa_erase_irq(&mb_chann->chan_xa, msg_id);
	if (!mb_msg) {
		MB_ERR(mb_chann, "Cannot find msg 0x%x", msg_id);
		return -EINVAL;
	}

	MB_DBG(mb_chann, "opcode 0x%x size %d id 0x%x",
	       header->opcode, header->total_size, header->id);
	ret = mb_msg->notify_cb(mb_msg->handle, data, header->total_size);
	if (unlikely(ret))
		MB_ERR(mb_chann, "Size %d opcode 0x%x ret %d",
		       header->total_size, header->opcode, ret);

	kfree(mb_msg);
	return ret;
}

/*
 * mailbox_get_msg() is the key function to get message from ring buffer.
 * If it returns 0, means 1 message was consumed.
 * If it returns -ENOENT, means ring buffer is emtpy.
 * If it returns other value, means ERROR.
 */
static int mailbox_get_msg(struct mailbox_channel *mb_chann)
{
	struct xdna_msg_header header;
	void __iomem *read_addr;
	u32 msg_size, rest;
	u32 ringbuf_size;
	u32 head, tail;
	u32 start_addr;
	int ret;

	tail = mailbox_get_tailptr(mb_chann, CHAN_RES_I2X);
	head = mb_chann->i2x_head;
	ringbuf_size = mailbox_get_ringbuf_size(mb_chann, CHAN_RES_I2X);
	start_addr = mb_chann->res[CHAN_RES_I2X].rb_start_addr;

	if (unlikely(tail > ringbuf_size || !IS_ALIGNED(tail, 4))) {
		MB_WARN_ONCE(mb_chann, "Invalid tail 0x%x", tail);
		return -EINVAL;
	}

	/* ringbuf empty */
	if (head == tail)
		return -ENOENT;

	if (head == ringbuf_size)
		head = 0;

	/* Peek size of the message or TOMBSTONE */
	read_addr = mb_chann->mb->res.ringbuf_base + start_addr + head;
	header.total_size = readl(read_addr);
	/* size is TOMBSTONE, set next read from 0 */
	if (header.total_size == TOMBSTONE) {
		if (head < tail) {
			MB_WARN_ONCE(mb_chann, "Tombstone, head 0x%x tail 0x%x",
				     head, tail);
			return -EINVAL;
		}

		mailbox_set_headptr(mb_chann, 0);
		return 0;
	}

	if (unlikely(!header.total_size || !IS_ALIGNED(header.total_size, 4))) {
		MB_WARN_ONCE(mb_chann, "Invalid total size 0x%x", header.total_size);
		return -EINVAL;
	}
	msg_size = sizeof(header) + header.total_size;

	if (msg_size > ringbuf_size - head || msg_size > tail - head) {
		MB_WARN_ONCE(mb_chann, "Invalid message size %d, tail %d, head %d",
			     msg_size, tail, head);
		return -EINVAL;
	}

	rest = sizeof(header) - sizeof(u32);
	read_addr += sizeof(u32);
	memcpy_fromio((u32 *)&header + 1, read_addr, rest);
	read_addr += rest;

	ret = mailbox_get_resp(mb_chann, &header, read_addr);

	mailbox_set_headptr(mb_chann, head + msg_size);
	/* After update head, it can equal to ringbuf_size. This is expected. */
	trace_mbox_set_head(MAILBOX_NAME, mb_chann->msix_irq,
			    header.opcode, header.id);
	return ret;
}

static void mailbox_rx_worker(struct work_struct *rx_work)
{
	struct mailbox_channel *mb_chann;
	u32 iohub;
	int ret;

	mb_chann = container_of(rx_work, struct mailbox_channel, rx_work);
	trace_mbox_rx_worker(MAILBOX_NAME, mb_chann->msix_irq);

	if (READ_ONCE(mb_chann->bad_state)) {
		MB_ERR(mb_chann, "Channel in bad state, work aborted");
		return;
	}

again:
	mailbox_irq_acknowledge(mb_chann);

	while (1) {
		/*
		 * If return is 0, keep consuming next message, until there is
		 * no messages or an error happened.
		 */
		ret = mailbox_get_msg(mb_chann);
		if (ret == -ENOENT)
			break;

		/* Other error means device doesn't look good, disable irq. */
		if (unlikely(ret)) {
			MB_ERR(mb_chann, "Unexpected ret %d, disable irq", ret);
			WRITE_ONCE(mb_chann->bad_state, true);
			disable_irq(mb_chann->msix_irq);
			return;
		}
	}

	/*
	 * The hardware will not generate interrupt if firmware creates a new
	 * response right after driver cleans up interrupt register. Check
	 * the interrupt register to make sure there is not any new response
	 * before exiting.
	 */
	iohub = mailbox_irq_status(mb_chann);
	if (iohub)
		goto again;
}

static irqreturn_t mailbox_irq_handler(int irq, void *p)
{
	struct mailbox_channel *mb_chann = p;

	trace_mbox_irq_handle(MAILBOX_NAME, irq);
	if (mb_chann->type == MB_CHANNEL_USER_POLL)
		return IRQ_HANDLED;

	/* Schedule a rx_work to call the callback functions */
	queue_work(mb_chann->work_q, &mb_chann->rx_work);

	return IRQ_HANDLED;
}

#ifdef AMDXDNA_DEVEL
static void mailbox_timer(struct timer_list *t)
{
#if defined from_timer
	struct mailbox_channel *mb_chann = from_timer(mb_chann, t, timer);
#elif defined timer_container_of
	struct mailbox_channel *mb_chann = timer_container_of(mb_chann, t, timer);
#endif
	u32 tail;

	/* The timer mimic interrupt. It is good to reuse irq routine */
	tail = mailbox_get_tailptr(mb_chann, CHAN_RES_I2X);
	if (tail)
		mailbox_irq_handler(0, mb_chann);

	mod_timer(&mb_chann->timer, jiffies + MB_TIMER_JIFF);
}
#endif

static inline int mailbox_has_more_msg(struct mailbox_channel *mb_chann)
{
	int ret;

	if (mb_chann->iohub_int_addr)
		return mailbox_irq_status(mb_chann);

	ret = mailbox_get_msg(mb_chann);
	if (ret == -ENOENT)
		return 0;

	if (unlikely(ret)) {
		MB_ERR(mb_chann, "Unexpected error on channel %d ret %d",
		       mb_chann->msix_irq, ret);
		WRITE_ONCE(mb_chann->bad_state, true);
		return 0;
	}

	return 1;
}

static void mailbox_polld_handle_chann(struct mailbox_channel *mb_chann)
{
	int ret;

	if (mb_chann->bad_state)
		return;

	ret = mailbox_has_more_msg(mb_chann);
	if (!ret)
		return;

	trace_mbox_poll_handle(MAILBOX_NAME, mb_chann->msix_irq);

	/* Clear pending events */
	mailbox_irq_acknowledge(mb_chann);

	/*
	 * Consider the race with FW, host needs to handle all messages sent
	 * before clear iohub register. But host is not able to exactly
	 * know which message was sent before clear iohub.
	 *
	 * Based on the fact that mb->polld is running much faster than FW,
	 * to simplify the design, just use below loop to consume all messages,
	 * It should exit in a reasonable time.
	 * Other channels should not be starved.
	 */
	do {
		ret = mailbox_get_msg(mb_chann);
	} while (!ret);

	if (ret == -ENOENT)
		return;

	if (unlikely(ret)) {
		MB_ERR(mb_chann, "Unexpected error on channel %d ret %d",
		       mb_chann->msix_irq, ret);
		WRITE_ONCE(mb_chann->bad_state, true);
	}
}

static void mailbox_polld_wakeup(struct mailbox *mb)
{
	wake_up(&mb->poll_wait);
}

static bool mailbox_polld_event(struct mailbox *mb)
{
	struct mailbox_channel *mb_chann;

	spin_lock(&mb->mbox_lock);
	list_for_each_entry(mb_chann, &mb->poll_chann_list, chann_entry) {
		if (mb_chann->type == MB_CHANNEL_MGMT)
			break;

		if (mailbox_channel_no_msg(mb_chann))
			continue;

		mb->sent_msg = true;
		break;
	}
	spin_unlock(&mb->mbox_lock);

	return mb->sent_msg;
}

static int mailbox_polld(void *data)
{
	struct mailbox *mb = (struct mailbox *)data;
	struct mailbox_channel *mb_chann;
	int loop_cnt = 0;

	dev_dbg(mb->dev, "polld start");
	while (!kthread_should_stop()) {
		bool chann_all_empty;

		wait_event_interruptible(mb->poll_wait, mailbox_polld_event(mb) ||
					 kthread_should_stop());

		if (!mb->sent_msg)
			continue;

		spin_lock(&mb->mbox_lock);
		chann_all_empty = true;
		list_for_each_entry(mb_chann, &mb->poll_chann_list, chann_entry) {
			if (mb_chann->type == MB_CHANNEL_MGMT)
				break;

			if (mailbox_channel_no_msg(mb_chann))
				continue;

			chann_all_empty = false;
			mailbox_polld_handle_chann(mb_chann);
		}
		spin_unlock(&mb->mbox_lock);

		if (chann_all_empty)
			mb->sent_msg = false;

		loop_cnt++;
		if (loop_cnt == 10) {
			loop_cnt = 0;
			schedule();
		}
	}
	dev_dbg(mb->dev, "polld stop");

	return 0;
}

int xdna_mailbox_send_msg(struct mailbox_channel *mb_chann,
			  struct xdna_mailbox_msg *msg, u64 tx_timeout)
{
	struct xdna_msg_header *header;
	struct mailbox_msg *mb_msg;
	size_t pkg_size;
	int ret;

	pkg_size = sizeof(*header) + msg->send_size;
	if (pkg_size > mailbox_get_ringbuf_size(mb_chann, CHAN_RES_X2I)) {
		MB_ERR(mb_chann, "Message size larger than ringbuf size");
		return -EINVAL;
	}

	if (unlikely(!IS_ALIGNED(msg->send_size, 4))) {
		MB_ERR(mb_chann, "Message must be 4 bytes align");
		return -EINVAL;
	}

	/* The fist word in payload can NOT be TOMBSTONE */
	if (unlikely(((u32 *)msg->send_data)[0] == TOMBSTONE)) {
		MB_ERR(mb_chann, "Tomb stone in data");
		return -EINVAL;
	}

	if (READ_ONCE(mb_chann->bad_state)) {
		MB_ERR(mb_chann, "Channel in bad state");
		return -EPIPE;
	}

	mb_msg = kzalloc(sizeof(*mb_msg) + pkg_size, GFP_KERNEL);
	if (!mb_msg)
		return -ENOMEM;

	mb_msg->handle = msg->handle;
	mb_msg->notify_cb = msg->notify_cb;
	mb_msg->pkg_size = pkg_size;

	header = &mb_msg->pkg.header;
	/*
	 * Hardware use total_size and size to split huge message.
	 * We do not support it here. Thus the values are the same.
	 */
	header->total_size = msg->send_size;
	header->sz_ver = FIELD_PREP(MSG_BODY_SZ, msg->send_size) |
			FIELD_PREP(MSG_PROTO_VER, MSG_PROTOCOL_VERSION);
	header->opcode = msg->opcode;
	memcpy(mb_msg->pkg.payload, msg->send_data, msg->send_size);

	ret = mailbox_acquire_msgid(mb_chann, mb_msg);
	if (unlikely(ret < 0)) {
		MB_ERR(mb_chann, "mailbox_acquire_msgid failed");
		goto msg_id_failed;
	}
	header->id = ret;
	msg->id = header->id;

	MB_DBG(mb_chann, "opcode 0x%x size %d id 0x%x",
	       header->opcode, header->total_size, header->id);

	ret = mailbox_send_msg(mb_chann, mb_msg);
	if (ret) {
		MB_DBG(mb_chann, "Error in mailbox send msg, ret %d", ret);
		goto release_id;
	}

	if (mb_chann->type == MB_CHANNEL_USER_POLL)
		mailbox_polld_wakeup(mb_chann->mb);
	return 0;

release_id:
	mailbox_release_msgid(mb_chann, header->id);
msg_id_failed:
	kfree(mb_msg);
	return ret;
}

#if defined(CONFIG_DEBUG_FS)
static struct mailbox_res_record *
xdna_mailbox_get_record(struct mailbox *mb, int mb_irq,
			const struct xdna_mailbox_chann_res *x2i,
			const struct xdna_mailbox_chann_res *i2x,
			enum xdna_mailbox_channel_type type)
{
	struct mailbox_res_record *record;
	int record_found = 0;

	spin_lock(&mb->mbox_lock);
	list_for_each_entry(record, &mb->res_records, re_entry) {
		if (record->re_irq != mb_irq)
			continue;

		record_found = 1;
		break;
	}
	spin_unlock(&mb->mbox_lock);

	if (record_found) {
		record->type = type;
		goto found;
	}

	record = kzalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return record;

	spin_lock(&mb->mbox_lock);
	list_add_tail(&record->re_entry, &mb->res_records);
	spin_unlock(&mb->mbox_lock);
	record->re_irq = mb_irq;

found:
	record->type = type;
	memcpy(&record->re_x2i, x2i, sizeof(*x2i));
	memcpy(&record->re_i2x, i2x, sizeof(*i2x));
	return record;
}

int xdna_mailbox_info_show(struct mailbox *mb, struct seq_file *m)
{
	static const char ring_fmt[] = "%4d  %3s  %5d  %4d  0x%08x  0x%04x  ";
	static const char mbox_fmt[] = "0x%08x  0x%08x  0x%04x    0x%04x\n";
	struct mailbox_res_record *record;

	/* If below two puts changed, make sure update fmt[] as well */
	seq_puts(m, "mbox  dir  alive  type  ring addr   size    ");
	seq_puts(m, "head ptr    tail ptr    head val  tail val\n");

#define xdna_mbox_dump_queue(_dir, _act) \
{ \
	u32 head_ptr, tail_ptr, head_val, tail_val; \
	u32 rb_start, rb_size; \
	u32 mbox_irq; \
	u32 type; \
	type = record->type; \
	mbox_irq = record->re_irq; \
	rb_start = record->re_##_dir.rb_start_addr; \
	rb_size = record->re_##_dir.rb_size; \
	head_ptr = record->re_##_dir.mb_head_ptr_reg; \
	tail_ptr = record->re_##_dir.mb_tail_ptr_reg; \
	head_val = ioread32((void *)(mb->res.mbox_base + head_ptr)); \
	tail_val = ioread32((void *)(mb->res.mbox_base + tail_ptr)); \
	seq_printf(m, ring_fmt, mbox_irq, #_dir, _act, type, rb_start, rb_size); \
	seq_printf(m, mbox_fmt, head_ptr, tail_ptr, head_val, tail_val); \
}

	spin_lock(&mb->mbox_lock);
	list_for_each_entry(record, &mb->res_records, re_entry) {
		xdna_mbox_dump_queue(x2i, record->active);
		xdna_mbox_dump_queue(i2x, record->active);
	}
	spin_unlock(&mb->mbox_lock);

	return 0;
}

int xdna_mailbox_ringbuf_show(struct mailbox *mb, struct seq_file *m)
{
	struct mailbox_res_record *record;
	const int size = 1024;
	void __iomem *base;
	char pfx[15];
	void *buf;

	buf = vzalloc(size);
	if (!buf)
		return -ENOMEM;

#define xdna_mbox_dump_ringbuf(_dir) \
	do { \
		snprintf(pfx, sizeof(pfx), "%s %d: ", #_dir, record->re_irq); \
		memcpy_fromio(buf, base + record->re_##_dir.rb_start_addr, size); \
		seq_hex_dump(m, pfx, DUMP_PREFIX_OFFSET, 16, 4, buf, size, true); \
	} while (0)
	spin_lock(&mb->mbox_lock);
	base = (void *)mb->res.ringbuf_base;
	list_for_each_entry(record, &mb->res_records, re_entry) {
		xdna_mbox_dump_ringbuf(x2i);
		xdna_mbox_dump_ringbuf(i2x);
	}
	spin_unlock(&mb->mbox_lock);

	vfree(buf);
	return 0;
}
#endif /* CONFIG_DEBUG_FS */

struct mailbox_channel *
xdna_mailbox_create_channel(struct mailbox *mb,
			    struct xdna_mailbox_chann_info *info,
			    enum xdna_mailbox_channel_type type)
{
	struct xdna_mailbox_chann_res *x2i = &info->x2i;
	struct xdna_mailbox_chann_res *i2x = &info->i2x;
	u32 iohub_int_addr = info->intr_reg;
	struct mailbox_channel *mb_chann;
	u32 mb_irq;
	int ret;

	ret = pci_irq_vector(to_pci_dev(mb->dev), info->msix_id);
	if (ret < 0) {
		pr_err("failed to alloc irq vector %d", ret);
		return NULL;
	}
	mb_irq = ret;

#if defined(CONFIG_DEBUG_FS)
	struct mailbox_res_record *record;
	/* Record will be released when mailbox device destroy*/
	record = xdna_mailbox_get_record(mb, mb_irq, x2i, i2x, type);
	if (!record)
		return NULL;
#endif /* CONFIG_DEBUG_FS */

	if (!is_power_of_2(x2i->rb_size) || !is_power_of_2(i2x->rb_size)) {
		pr_err("Ring buf size must be power of 2");
		return NULL;
	}

	mb_chann = kzalloc(sizeof(*mb_chann), GFP_KERNEL);
	if (!mb_chann)
		return NULL;

	mb_chann->mb = mb;
	mb_chann->type = type;
#ifdef AMDXDNA_DEVEL
	if (type != MB_CHANNEL_MGMT && MB_FORCE_USER_POLL)
		mb_chann->type = MB_CHANNEL_USER_POLL;
#endif
	mb_chann->msix_irq = mb_irq;
	mb_chann->iohub_int_addr = iohub_int_addr;
	memcpy(&mb_chann->res[CHAN_RES_X2I], x2i, sizeof(*x2i));
	memcpy(&mb_chann->res[CHAN_RES_I2X], i2x, sizeof(*i2x));

	xa_init_flags(&mb_chann->chan_xa, XA_FLAGS_ALLOC | XA_FLAGS_LOCK_IRQ);
	mb_chann->x2i_tail = mailbox_get_tailptr(mb_chann, CHAN_RES_X2I);
	mb_chann->i2x_head = mailbox_get_headptr(mb_chann, CHAN_RES_I2X);
	/* Clear pending events */
	mailbox_irq_acknowledge(mb_chann);

	INIT_WORK(&mb_chann->rx_work, mailbox_rx_worker);
	mb_chann->work_q = alloc_ordered_workqueue(MAILBOX_NAME, 0);
	if (!mb_chann->work_q) {
		MB_ERR(mb_chann, "Create workqueue failed");
		goto free_and_out;
	}

#ifdef AMDXDNA_DEVEL
	if (MB_PERIODIC_POLL) {
		/* Poll response every few ms. Good for bring up a new device */
		timer_setup(&mb_chann->timer, mailbox_timer, 0);

		mb_chann->timer.expires = jiffies + MB_TIMER_JIFF;
		add_timer(&mb_chann->timer);
		MB_DBG(mb_chann, "Poll in every %d msecs", mailbox_polling);
		goto skip_irq;
	}
#endif
	/* Everything look good. Time to enable irq handler */
	ret = request_irq(mb_irq, mailbox_irq_handler, 0, MAILBOX_NAME, mb_chann);
	if (ret) {
		MB_ERR(mb_chann, "Failed to request irq %d ret %d", mb_irq, ret);
		goto destroy_wq;
	}

#ifdef AMDXDNA_DEVEL
skip_irq:
#endif
	mb_chann->bad_state = false;
	spin_lock(&mb->mbox_lock);
	if (mb_chann->type == MB_CHANNEL_USER_POLL)
		list_add_tail(&mb_chann->chann_entry, &mb->poll_chann_list);
	else
		list_add_tail(&mb_chann->chann_entry, &mb->chann_list);
#if defined(CONFIG_DEBUG_FS)
	mb_chann->record = record;
	record->active = 1;
#endif
	spin_unlock(&mb->mbox_lock);

	MB_DBG(mb_chann, "Mailbox channel created type %d (irq: %d)",
	       mb_chann->type, mb_chann->msix_irq);
	return mb_chann;

destroy_wq:
	destroy_workqueue(mb_chann->work_q);
free_and_out:
	kfree(mb_chann);
	return NULL;
}

void xdna_mailbox_release_channel(struct mailbox_channel *mb_chann)
{
	struct mailbox_msg *mb_msg;
	unsigned long msg_id;

	if (!mb_chann)
		return;

	spin_lock(&mb_chann->mb->mbox_lock);
	list_del(&mb_chann->chann_entry);
#if defined(CONFIG_DEBUG_FS)
	mb_chann->record->active = 0;
#endif
	spin_unlock(&mb_chann->mb->mbox_lock);

#ifdef AMDXDNA_DEVEL
	if (MB_PERIODIC_POLL)
		goto destroy_wq;
#endif
	free_irq(mb_chann->msix_irq, mb_chann);

#ifdef AMDXDNA_DEVEL
destroy_wq:
#endif
	destroy_workqueue(mb_chann->work_q);
	/* We can clean up and release resources */

	xa_for_each(&mb_chann->chan_xa, msg_id, mb_msg)
		mailbox_release_msg(mb_chann, mb_msg);

	MB_DBG(mb_chann, "Mailbox channel released type %d irq: %d",
	       mb_chann->type, mb_chann->msix_irq);
}

void xdna_mailbox_free_channel(struct mailbox_channel *mb_chann)
{
	if (!mb_chann)
		return;

	xa_destroy(&mb_chann->chan_xa);
	kfree(mb_chann);
}

void xdna_mailbox_stop_channel(struct mailbox_channel *mb_chann)
{
	if (!mb_chann)
		return;

#ifdef AMDXDNA_DEVEL
	if (MB_PERIODIC_POLL) {
		timer_delete_sync(&mb_chann->timer);
		goto skip_irq;
	}
#endif
	/* Disable an irq and wait. This might sleep. */
	disable_irq(mb_chann->msix_irq);

#ifdef AMDXDNA_DEVEL
skip_irq:
#endif
	/* Cancel RX work and wait for it to finish */
	cancel_work_sync(&mb_chann->rx_work);
	MB_DBG(mb_chann, "IRQ disabled and RX work cancelled");
}

void xdna_mailbox_destroy_channel(struct mailbox_channel *mailbox_chann)
{
	xdna_mailbox_release_channel(mailbox_chann);
	xdna_mailbox_free_channel(mailbox_chann);
}

struct mailbox *xdna_mailbox_create(struct device *dev,
				    const struct xdna_mailbox_res *res)
{
	struct mailbox *mb;

	mb = kzalloc(sizeof(*mb), GFP_KERNEL);
	if (!mb)
		return NULL;
	mb->dev = dev;

	/* mailbox and ring buf base and size information */
	memcpy(&mb->res, res, sizeof(*res));

	spin_lock_init(&mb->mbox_lock);
	INIT_LIST_HEAD(&mb->chann_list);
	INIT_LIST_HEAD(&mb->poll_chann_list);
	init_waitqueue_head(&mb->poll_wait);
	mb->sent_msg = false;

#if defined(CONFIG_DEBUG_FS)
	INIT_LIST_HEAD(&mb->res_records);
#endif /* CONFIG_DEBUG_FS */

	/*
	 * The polld kthread will only wakeup and handle those
	 * MB_CHANNEL_USER_POLL channels. If nothing to do, polld should
	 * just sleep. It is a per device kthread.
	 *
	 * Note: make sure polld is the last thing to initialize.
	 */
	mb->polld = kthread_run(mailbox_polld, mb, MAILBOX_NAME);
	if (IS_ERR(mb->polld)) {
		dev_err(mb->dev, "Failed to create polld ret %ld", PTR_ERR(mb->polld));
		kfree(mb);
		return NULL;
	}

	return mb;
}

void xdna_mailbox_destroy(struct mailbox *mb)
{
#if defined(CONFIG_DEBUG_FS)
	struct mailbox_res_record *record;
	struct mailbox_res_record *next;

	if (list_empty(&mb->res_records))
		goto done_release_record;

	list_for_each_entry_safe(record, next, &mb->res_records, re_entry) {
		list_del(&record->re_entry);
		kfree(record);
	}
done_release_record:
#endif /* CONFIG_DEBUG_FS */
	dev_dbg(mb->dev, "Stopping polld");
	(void)kthread_stop(mb->polld);

	spin_lock(&mb->mbox_lock);
	WARN_ONCE(!list_empty(&mb->chann_list), "Channel not destroy");
	spin_unlock(&mb->mbox_lock);

	kfree(mb);
}
