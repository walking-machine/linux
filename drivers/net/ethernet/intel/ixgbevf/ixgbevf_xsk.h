/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 1999 - 2024 Intel Corporation. */

#ifndef _IXGBEVF_XSK_H_
#define _IXGBEVF_XSK_H_

int ixgbevf_clean_xsk_rx_irq(struct ixgbevf_q_vector *q_vector,
                         struct ixgbevf_ring *rx_ring, int budget);
bool ixgbevf_clean_xsk_tx_irq(struct ixgbevf_q_vector *q_vector,
                              struct ixgbevf_ring *tx_ring, int napi_budget);
void ixgbevf_xsk_alloc_rx_bufs(struct ixgbevf_ring *rx_ring, u32 num);
void ixgbevf_rx_xsk_ring_free_buffs(struct ixgbevf_ring *rx_ring);
int ixgbevf_xsk_wakeup(struct net_device *dev, u32 queue_id, u32 flags);


#endif /* _IXGBEVF_XSK_H_ */
