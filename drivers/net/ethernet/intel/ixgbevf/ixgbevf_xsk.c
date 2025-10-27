// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2026 Intel Corporation */

#include <net/libeth/xsk.h>

#include "ixgbevf.h"
#include "ixgbevf_xsk.h"

/**
 * ixgbevf_single_irq_disable - Mask off interrupt generation on a single vector
 * @adapter: board private structure
 * @vidx: vector id
 **/
static void ixgbevf_single_irq_disable(struct ixgbevf_adapter *adapter,
				       u16 vidx)
{
	struct ixgbe_hw *hw = &adapter->hw;

	IXGBE_WRITE_REG(hw, IXGBE_VTEIAM,
			adapter->eims_enable_mask & ~BIT(vidx));
	IXGBE_WRITE_REG(hw, IXGBE_VTEIMC, BIT(vidx));
	IXGBE_WRITE_REG(hw, IXGBE_VTEIAC,
			adapter->eims_enable_mask & ~BIT(vidx));

	IXGBE_WRITE_FLUSH(hw);

	synchronize_irq(adapter->msix_entries[vidx].vector);
}

static void ixgbevf_qp_dis(struct ixgbevf_adapter *adapter, u16 qid)
{
	struct ixgbevf_ring *tx_ring, *rx_ring = adapter->rx_ring[qid];
	struct ixgbevf_q_vector *q_vector = rx_ring->q_vector;

	netif_stop_subqueue(adapter->netdev, qid);
	ixgbevf_single_irq_disable(adapter, q_vector->v_idx);
	napi_disable(&q_vector->napi);

	synchronize_net();

	ixgbevf_disable_rx_queue(adapter, adapter->rx_ring[qid]);
	ixgbevf_clean_rx_ring(rx_ring);
	ixgbevf_rx_destroy_pp(rx_ring);

	/* Clean both XDP and normal Tx queue */
	ixgbevf_for_each_ring(tx_ring, q_vector->tx) {
		ixgbevf_flush_tx_queue(tx_ring);
		if (ring_is_xdp(tx_ring))
			ixgbevf_clean_xdp_ring(tx_ring);
		else
			ixgbevf_clean_tx_ring(tx_ring);
	}
}

static void ixgbevf_qp_ena(struct ixgbevf_adapter *adapter, u16 qid)
{
	struct ixgbevf_ring *tx_ring, *rx_ring = adapter->rx_ring[qid];
	struct ixgbevf_q_vector *q_vector = rx_ring->q_vector;

	ixgbevf_configure_rx_ring(adapter, rx_ring);
	ixgbevf_for_each_ring(tx_ring, q_vector->tx)
		ixgbevf_configure_tx_ring(adapter, tx_ring);

	napi_enable(&q_vector->napi);
	ixgbevf_irq_enable(adapter);
	netif_start_subqueue(adapter->netdev, qid);
}

int ixgbevf_setup_xsk_pool(struct ixgbevf_adapter *adapter,
			   struct xsk_buff_pool *pool, u16 qid)
{
	bool running = !test_bit(__IXGBEVF_DOWN, &adapter->state) &&
		       adapter->xdp_prog;
	int err;

	if (running)
		ixgbevf_qp_dis(adapter, qid);

	err = libeth_xsk_setup_pool(adapter->netdev, qid, !!pool);

	if (running)
		ixgbevf_qp_ena(adapter, qid);

	return err;
}

static void ixgbevf_fill_rx_xsk_desc(const struct libeth_xskfq_fp *fq, u32 i)
{
	union ixgbe_adv_rx_desc *rx_desc =
		&((union ixgbe_adv_rx_desc *)fq->descs)[i];

	rx_desc->read.pkt_addr =
		cpu_to_le64(libeth_xsk_buff_xdp_get_dma(fq->fqes[i]));
	rx_desc->wb.upper.length = 0;
}

void ixgbevf_xsk_alloc_rx_bufs(struct ixgbevf_ring *rx_ring, u32 num)
{
	struct libeth_xskfq_fp fq = {
		.count = rx_ring->count,
		.descs = rx_ring->desc,
		.fqes = rx_ring->xsk_fqes,
		.ntu = rx_ring->next_to_use,
		.pool = rx_ring->xsk_pool,
	};
	u32 done;

	done = libeth_xskfqe_alloc(&fq, num, ixgbevf_fill_rx_xsk_desc);
	if (likely(done)) {
		/* Finish descriptor writes before bumping tail */
		wmb();
		ixgbevf_write_tail(rx_ring, fq.ntu);
	}

	rx_ring->next_to_use = fq.ntu;
	rx_ring->pending -= done;
}

void ixgbevf_rx_xsk_ring_free_buffs(struct ixgbevf_ring *rx_ring)
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
