/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2010-2026 Intel Corporation */

#ifndef _IXGBEVF_XDP_LIB_H_
#define _IXGBEVF_XDP_LIB_H_

#include <linux/net/intel/libie/xg_xdp.h>

#include "ixgbevf.h"

static inline u32 ixgbevf_prep_xdp_sq(void *xdpsq, struct libeth_xdpsq *sq)
{
	struct ixgbevf_ring *xdp_ring = xdpsq;

	libeth_xdpsq_lock(&xdp_ring->xdpq_lock);
	if (unlikely(ixgbevf_desc_unused(xdp_ring) < xdp_ring->thresh)) {
		u16 to_clean = libie_xg_tx_get_num_sent(xdpsq);

		if (likely(to_clean))
			libie_xg_clean_xdp_num(&xdp_ring->base, true, to_clean,
					       ring_is_xsk(xdp_ring));
	}

	if (unlikely(!test_bit(__IXGBEVF_TX_XDP_RING_PRIMED,
			       &xdp_ring->state))) {
		struct ixgbe_adv_tx_context_desc *context_desc;

		set_bit(__IXGBEVF_TX_XDP_RING_PRIMED, &xdp_ring->state);

		context_desc = IXGBEVF_TX_CTXTDESC(xdp_ring, 0);
		context_desc->vlan_macip_lens	=
			cpu_to_le32(ETH_HLEN << IXGBE_ADVTXD_MACLEN_SHIFT);
		context_desc->fceof_saidx	= 0;
		context_desc->type_tucmd_mlhl	=
			cpu_to_le32(IXGBE_TXD_CMD_DEXT |
				    IXGBE_ADVTXD_DTYP_CTXT);
		context_desc->mss_l4len_idx	= 0;

		xdp_ring->next_to_use = 1;
		xdp_ring->pending = 1;
		xdp_ring->xdp_sqes[0].type = LIBETH_SQE_CTX;

		/* Finish descriptor writes before bumping tail */
		wmb();
		ixgbevf_write_tail(xdp_ring, 1);
	}

	*sq = (struct libeth_xdpsq) {
		.count = xdp_ring->count,
		.descs = xdp_ring->desc,
		.lock = &xdp_ring->xdpq_lock,
		.ntu = &xdp_ring->next_to_use,
		.pending = &xdp_ring->pending,
		.pool = xdp_ring->xsk_pool,
		.sqes = xdp_ring->xdp_sqes,
	};

	return ixgbevf_desc_unused(xdp_ring);
}

#endif /* _IXGBEVF_XDP_LIB_H_ */
