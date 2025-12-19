/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Intel Corporation */

#ifndef _IXGBEVF_XSK_H_
#define _IXGBEVF_XSK_H_

/* Process completions as soon as possible */
#define IXGBEVF_XSK_TX_CLEAN_THRESH(r)	((r)->count - 1)
#define IXGBEVF_XSK_MAX_ZC_FRAGS	min(18, MAX_SKB_FRAGS)

int ixgbevf_setup_xsk_pool(struct ixgbevf_adapter *adapter,
			   struct xsk_buff_pool *pool, u16 qid);
bool ixgbevf_xsk_alloc_rx_bufs(struct ixgbevf_ring *rx_ring, u32 num);
void ixgbevf_rx_xsk_ring_free_buffs(struct ixgbevf_ring *rx_ring);
u32 ixgbevf_clean_xsk_rx_irq(struct ixgbevf_q_vector *q_vector,
			     struct ixgbevf_ring *rx_ring, int budget);
bool ixgbevf_clean_xsk_tx_irq(struct ixgbevf_q_vector *q_vector,
			      struct ixgbevf_ring *tx_ring, int napi_budget);
int ixgbevf_xsk_wakeup(struct net_device *dev, u32 queue_id, u32 flags);

#endif /* _IXGBEVF_XSK_H_ */
