/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Intel Corporation */

#ifndef _IXGBEVF_XSK_H_
#define _IXGBEVF_XSK_H_

int ixgbevf_setup_xsk_pool(struct ixgbevf_adapter *adapter,
			   struct xsk_buff_pool *pool, u16 qid);
void ixgbevf_xsk_alloc_rx_bufs(struct ixgbevf_ring *rx_ring, u32 num);
void ixgbevf_rx_xsk_ring_free_buffs(struct ixgbevf_ring *rx_ring);

#endif /* _IXGBEVF_XSK_H_ */
