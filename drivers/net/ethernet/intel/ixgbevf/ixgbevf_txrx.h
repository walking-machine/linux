/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Intel Corporation */

#ifndef _IXGBEVF_TXRX_H_
#define _IXGBEVF_TXRX_H_

#include "ixgbevf.h"

/**
 * ixgbevf_is_non_eop - process handling of non-EOP buffers
 * @rx_ring: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 *
 * This function updates next to clean.  If the buffer is an EOP buffer
 * this function exits returning false, otherwise it will place the
 * sk_buff in the next buffer to be chained and return true indicating
 * that this is in fact a non-EOP buffer.
 **/
static inline bool ixgbevf_is_non_eop(struct ixgbevf_ring *rx_ring,
				      union ixgbe_adv_rx_desc *rx_desc)
{
	u32 ntc = rx_ring->next_to_clean + 1;

	/* fetch, update, and store next to clean */
	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;
	rx_ring->pending++;

	prefetch(IXGBEVF_RX_DESC(rx_ring, ntc));

	if (likely(ixgbevf_test_staterr(rx_desc, IXGBE_RXD_STAT_EOP)))
		return false;

	return true;
}

bool ixgbevf_cleanup_headers(struct ixgbevf_ring *rx_ring,
                             union ixgbe_adv_rx_desc *rx_desc,
                             struct sk_buff *skb);
void ixgbevf_process_skb_fields(struct ixgbevf_ring *rx_ring,
				union ixgbe_adv_rx_desc *rx_desc,
				struct sk_buff *skb);

#endif /* _IXGBEVF_TXRX_H_ */
