/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Intel Corporation */

#ifndef __LIBIE_XG_RING_H
#define __LIBIE_XG_RING_H

#include <linux/u64_stats_sync.h>
#include <net/libeth/types.h>
#include <net/xdp.h>

#include <linux/net/intel/ixgbe_desc_common.h>

struct libie_xg_queue_stats {
	u64 packets;
	u64 bytes;
};

struct libie_xg_tx_queue_stats {
	u64 restart_queue;
	u64 tx_busy;
	u64 tx_done_old;
};

struct libie_xg_rx_queue_stats {
	/* u64 rsc_count; <- was in ixgbe
	u64 rsc_flush; */
	u64 non_eop_descs;
	u64 alloc_rx_page;
	u64 alloc_rx_page_failed;
	u64 alloc_rx_buff_failed;
	u64 csum_err;
};

struct libie_xg_tx_buffer {
	union ixgbe_adv_tx_desc *next_to_watch;
	unsigned long time_stamp;
	union {
		struct sk_buff *skb;
		/* XDP uses address ptr on irq_clean */
		void *data;
	};
	unsigned int bytecount;
	unsigned short gso_segs;
	__be16 protocol;
	DEFINE_DMA_UNMAP_ADDR(dma);
	DEFINE_DMA_UNMAP_LEN(len);
	u32 tx_flags;
};

struct libie_xg_ring {
	struct device *dev;	/* Tx ring */
	union {
		struct page_pool *pp;	/* Rx and XDP rings */
		struct xsk_buff_pool *xsk_pool; /* AF_XDP ZC rings */
	};
	void *desc;			/* descriptor ring memory */
	u16 count;			/* amount of descriptors */
	u16 next_to_clean;
	u32 next_to_use;
	u32 pending;			/* Sent-not-completed descriptors */
	u32 cached_ntu;

	union {
		struct libeth_fqe *rx_fqes;
		struct libeth_xdp_buff	**xsk_fqes;
		struct libie_xg_tx_buffer *tx_buffer_info;
		struct libeth_sqe *xdp_sqes;
	};
	u8 __iomem *tail;

	struct libeth_xdp_buff *xsk_xdp_head;
	struct libeth_xdpsq_lock xdpq_lock;
};

#define LIBIE_XG_RX_DESC(R, i)	\
	(&(((union ixgbe_adv_rx_desc *)((R)->desc))[i]))
#define LIBIE_XG_TX_DESC(R, i)	\
	(&(((union ixgbe_adv_tx_desc *)((R)->desc))[i]))
#define LIBIE_XG_TX_CTXTDESC(R, i)	\
	(&(((struct ixgbe_adv_tx_context_desc *)((R)->desc))[i]))

#endif