/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Intel Corporation */

#ifndef __LIBIE_XG_XDP_H
#define __LIBIE_XG_XDP_H

#include <linux/net/intel/libie/xg_ring.h>
#include <net/libeth/xsk.h>

static inline void libie_xg_fill_rx_xsk_desc(const struct libeth_xskfq_fp *fq, u32 i)
{
	union ixgbe_adv_rx_desc *rx_desc =
		&((union ixgbe_adv_rx_desc *)fq->descs)[i];

	rx_desc->read.pkt_addr =
		cpu_to_le64(libeth_xsk_buff_xdp_get_dma(fq->fqes[i]));
	rx_desc->wb.upper.length = 0;
}

static inline bool libie_xg_xsk_alloc_rx_bufs(struct libie_xg_ring *rx_ring,
                                              u32 num)
{
	struct libeth_xskfq_fp fq = {
		.count = rx_ring->count,
		.descs = rx_ring->desc,
		.fqes = rx_ring->xsk_fqes,
		.ntu = rx_ring->next_to_use,
		.pool = rx_ring->xsk_pool,
	};
	u32 done;

	done = libeth_xskfqe_alloc(&fq, num, libie_xg_fill_rx_xsk_desc);
	if (likely(done)) {
		/* Finish descriptor writes before bumping tail */
		wmb();
                writel(fq.ntu, rx_ring->tail);
	}

	/* Prevent ntc circling past ntu, e.g. in case of starvation */
	LIBIE_XG_RX_DESC(rx_ring, fq.ntu)->wb.upper.length = 0;

	rx_ring->next_to_use = fq.ntu;
	rx_ring->pending -= done;

	return done == num;
}

static inline void libie_xg_rx_xsk_ring_free_buffs(struct libie_xg_ring *rx_ring)
{
	u32 ntc = rx_ring->next_to_clean;

	if (rx_ring->xsk_xdp_head)
		xsk_buff_free(&rx_ring->xsk_xdp_head->base);

	rx_ring->xsk_xdp_head = NULL;

	while (ntc != rx_ring->next_to_use) {
		xsk_buff_free(&rx_ring->xsk_fqes[ntc]->base);
		ntc++;
		ntc = ntc == rx_ring->count ? 0 : ntc;
	}
}

struct libie_xg_zc_sqe_priv {
	u16 first_desc;
	u16 len;
};

LIBETH_SQE_CHECK_PRIV(struct libie_xg_zc_sqe_priv);

static inline void libie_xg_xsk_xmit_desc(struct libeth_xdp_tx_desc desc, u32 i,
				          const struct libeth_xdpsq *sq,
                                          u64 priv)
{
	union ixgbe_adv_tx_desc *descs = sq->descs, *tx_desc = &descs[i];
	u32 ltu = (i ? : sq->count) - 1;

	u32 cmd_type = IXGBE_ADVTXD_DTYP_DATA |
		       IXGBE_ADVTXD_DCMD_DEXT |
		       IXGBE_ADVTXD_DCMD_IFCS |
		       desc.len;

	tx_desc->read.buffer_addr = cpu_to_le64(desc.addr);

	if (likely((desc.flags & LIBETH_XDP_TX_LAST) && !sq->sqes[ltu].priv)) {
		tx_desc->read.olinfo_status =
			cpu_to_le32((desc.len << IXGBE_ADVTXD_PAYLEN_SHIFT) |
				    IXGBE_ADVTXD_CC);
		tx_desc->read.cmd_type_len =
			cpu_to_le32(cmd_type | IXGBE_TXD_CMD_EOP);
		return;
	}

	/* No previous packet */
	if (!sq->sqes[ltu].priv) {
		struct libie_xg_zc_sqe_priv *sqe_priv =
			                (void *)&sq->sqes[i].priv;

		sqe_priv->first_desc = i;
		sqe_priv->len = desc.len;

		tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);

		return;
	}

	if (sq->sqes[ltu].priv) {
		struct libie_xg_zc_sqe_priv *sqe_priv =
						(void *)&sq->sqes[i].priv;

		sq->sqes[i].priv = sq->sqes[ltu].priv;
		sq->sqes[ltu].priv = 0;
		sqe_priv->len += desc.len;

		if (desc.flags & LIBETH_XDP_TX_LAST) {
			union ixgbe_adv_tx_desc *first_desc =
						&descs[sqe_priv->first_desc];

			first_desc->read.olinfo_status =
				cpu_to_le32((sqe_priv->len <<
					     IXGBE_ADVTXD_PAYLEN_SHIFT) |
					    IXGBE_ADVTXD_CC);
			cmd_type |= IXGBE_TXD_CMD_EOP;
			sq->sqes[i].priv = 0;
		}

		tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);
	}
}

static inline void libie_xg_xdp_xmit_desc(struct libeth_xdp_tx_desc desc, u32 i,
					  const struct libeth_xdpsq *sq,
					  u64 priv)
{
	union ixgbe_adv_tx_desc *tx_desc =
		&((union ixgbe_adv_tx_desc *)sq->descs)[i];

	u32 cmd_type = IXGBE_ADVTXD_DTYP_DATA |
		       IXGBE_ADVTXD_DCMD_DEXT |
		       IXGBE_ADVTXD_DCMD_IFCS |
		       desc.len;

	if (desc.flags & LIBETH_XDP_TX_LAST)
		cmd_type |= IXGBE_TXD_CMD_EOP;

	if (desc.flags & LIBETH_XDP_TX_FIRST) {
		struct libeth_sqe *sqe = &sq->sqes[i];
		struct skb_shared_info *sinfo;
		u16 full_len = desc.len;

		if (desc.flags & LIBETH_XDP_TX_MULTI) {
			sinfo = sqe->type == LIBETH_SQE_XDP_TX ?
				sqe->sinfo :
				xdp_get_shared_info_from_frame(sqe->xdpf);
			full_len += sinfo->xdp_frags_size;
		}

		tx_desc->read.olinfo_status =
			cpu_to_le32((full_len << IXGBE_ADVTXD_PAYLEN_SHIFT) |
				    IXGBE_ADVTXD_CC);
	}

	tx_desc->read.buffer_addr = cpu_to_le64(desc.addr);
	tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);
}

static inline u16 libie_xg_tx_get_num_sent(struct libie_xg_ring *xdp_ring)
{
	u16 ntc = xdp_ring->next_to_clean;
	u16 to_clean = 0;

	while (likely(to_clean < xdp_ring->pending)) {
		u32 idx = xdp_ring->xdp_sqes[ntc].rs_idx;
		union ixgbe_adv_tx_desc *rs_desc;

		if (!idx--)
			break;

		rs_desc = LIBIE_XG_TX_DESC(xdp_ring, idx);

		if (!(rs_desc->wb.status & cpu_to_le32(IXGBE_TXD_STAT_DD)))
			break;

		xdp_ring->xdp_sqes[ntc].rs_idx = 0;

		to_clean +=
			(idx >= ntc ? idx : idx + xdp_ring->count) - ntc + 1;

		ntc = (idx + 1 == xdp_ring->count) ? 0 : idx + 1;
	}

	return to_clean;
}

static inline void libie_xg_clean_xdp_num(struct libie_xg_ring *xdp_ring,
					  bool in_napi, u16 to_clean, bool xsk_ring)
{
	struct libeth_xdpsq_napi_stats stats = { };
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

static inline void libie_xg_xdp_rs_and_bump(void *xdpsq, bool sent, bool flush)
{
	struct libie_xg_ring *xdp_ring = xdpsq;
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

	desc = LIBIE_XG_TX_DESC(xdp_ring, ltu);
	desc->read.cmd_type_len |= cpu_to_le32(IXGBE_TXD_CMD);

	xdp_ring->xdp_sqes[xdp_ring->cached_ntu].rs_idx = ltu + 1;
	xdp_ring->cached_ntu = xdp_ring->next_to_use;

	/* In case the packet was interrupted, discard it */
	xdp_ring->xdp_sqes[ltu].priv = 0;

	/* Finish descriptor writes before bumping tail */
	wmb();
        writel(xdp_ring->next_to_use, xdp_ring->tail);

unlock:
	libeth_xdpsq_unlock(&xdp_ring->xdpq_lock);
}

#endif