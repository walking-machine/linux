/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2010-2026 Intel Corporation */

#ifndef _IXGBEVF_XDP_LIB_H_
#define _IXGBEVF_XDP_LIB_H_

#include <net/libeth/xsk.h>

#include "ixgbevf.h"

static inline u16 ixgbevf_tx_get_num_sent(struct ixgbevf_ring *xdp_ring)
{
	u16 ntc = xdp_ring->next_to_clean;
	u16 to_clean = 0;

	while (likely(to_clean < xdp_ring->pending)) {
		u32 idx = xdp_ring->xdp_sqes[ntc].rs_idx;
		union ixgbe_adv_tx_desc *rs_desc;

		if (!idx--)
			break;

		rs_desc = IXGBEVF_TX_DESC(xdp_ring, idx);

		if (!(rs_desc->wb.status & cpu_to_le32(IXGBE_TXD_STAT_DD)))
			break;

		xdp_ring->xdp_sqes[ntc].rs_idx = 0;

		to_clean +=
			(idx >= ntc ? idx : idx + xdp_ring->count) - ntc + 1;

		ntc = (idx + 1 == xdp_ring->count) ? 0 : idx + 1;
	}

	return to_clean;
}

static inline void ixgbevf_clean_xdp_num(struct ixgbevf_ring *xdp_ring,
					 bool in_napi, u16 to_clean)
{
	struct libeth_xdpsq_napi_stats stats = { };
	bool xsk_ring = ring_is_xsk(xdp_ring);
	u32 ntc = xdp_ring->next_to_clean;
	struct xdp_frame_bulk cbulk;
	struct libeth_cq_pp cp = {
		.bq = &cbulk,
		.dev = xdp_ring->dev,
		.xss = &stats,
		.napi = in_napi,
	};
	u32 xsk_frames = 0;

	xdp_frame_bulk_init(&cbulk);
	xdp_ring->pending -= to_clean;

	while (likely(to_clean--)) {
		xsk_frames += xsk_ring &&
			likely(!xdp_ring->xdp_sqes[ntc].type) ? 1 : 0;
		libeth_xdp_complete_tx(&xdp_ring->xdp_sqes[ntc], &cp);
		ntc++;
		ntc = unlikely(ntc == xdp_ring->count) ? 0 : ntc;
	}

	xdp_ring->next_to_clean = ntc;
	xdp_flush_frame_bulk(&cbulk);
	if (xsk_frames)
		xsk_tx_completed(xdp_ring->xsk_pool, xsk_frames);
}

static inline u32 ixgbevf_prep_xdp_sq(void *xdpsq, struct libeth_xdpsq *sq)
{
	struct ixgbevf_ring *xdp_ring = xdpsq;

	libeth_xdpsq_lock(&xdp_ring->xdpq_lock);
	if (unlikely(ixgbevf_desc_unused(xdp_ring) < xdp_ring->thresh)) {
		u16 to_clean = ixgbevf_tx_get_num_sent(xdpsq);

		if (likely(to_clean))
			ixgbevf_clean_xdp_num(xdp_ring, true, to_clean);
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

static inline void ixgbevf_xdp_rs_and_bump(void *xdpsq, bool sent, bool flush)
{
	struct ixgbevf_ring *xdp_ring = xdpsq;
	union ixgbe_adv_tx_desc *desc;
	u32 ltu;

	libeth_xdpsq_lock(&xdp_ring->xdpq_lock);

	if ((!flush && xdp_ring->pending < xdp_ring->count - 1) ||
	    xdp_ring->cached_ntu == xdp_ring->next_to_use)
		goto unlock;

	ltu = (xdp_ring->next_to_use ? : xdp_ring->count) - 1;

	/* We will not get DD on a context descriptor */
	if (unlikely(xdp_ring->xdp_sqes[ltu].type == LIBETH_SQE_CTX))
		goto unlock;

	desc = IXGBEVF_TX_DESC(xdp_ring, ltu);
	desc->read.cmd_type_len |= cpu_to_le32(IXGBE_TXD_CMD);

	xdp_ring->xdp_sqes[xdp_ring->cached_ntu].rs_idx = ltu + 1;
	xdp_ring->cached_ntu = xdp_ring->next_to_use;

	/* Finish descriptor writes before bumping tail */
	wmb();
	ixgbevf_write_tail(xdp_ring, xdp_ring->next_to_use);

unlock:
	libeth_xdpsq_unlock(&xdp_ring->xdpq_lock);
}

#endif /* _IXGBEVF_XDP_LIB_H_ */
