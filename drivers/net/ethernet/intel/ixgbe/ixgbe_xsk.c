// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2018 Intel Corporation. */

#include <linux/bpf_trace.h>
#include <linux/net/intel/libie/xg_xdp.h>
#include <net/xdp_sock_drv.h>
#include <net/xdp.h>

#include "ixgbe.h"
#include "ixgbe_txrx_common.h"

struct xsk_buff_pool *ixgbe_xsk_pool(struct ixgbe_adapter *adapter,
				     struct ixgbe_ring *ring)
{
	bool xdp_on = READ_ONCE(adapter->xdp_prog);
	int qid = ring->ring_idx;

	if (!xdp_on || !test_bit(qid, adapter->af_xdp_zc_qps))
		return NULL;

	return xsk_get_pool_from_qid(adapter->netdev, qid);
}

static int ixgbe_xsk_pool_enable(struct ixgbe_adapter *adapter,
				 struct xsk_buff_pool *pool,
				 u16 qid)
{
	struct net_device *netdev = adapter->netdev;
	bool if_running;
	int err;

	if (qid >= adapter->num_rx_queues)
		return -EINVAL;

	if (qid >= netdev->real_num_rx_queues ||
	    qid >= netdev->real_num_tx_queues)
		return -EINVAL;

	err = xsk_pool_dma_map(pool, &adapter->pdev->dev, IXGBE_RX_DMA_ATTR);
	if (err)
		return err;

	if_running = netif_running(adapter->netdev) &&
		     ixgbe_enabled_xdp_adapter(adapter);

	if (if_running)
		ixgbe_txrx_ring_disable(adapter, qid);

	set_bit(qid, adapter->af_xdp_zc_qps);

	if (if_running) {
		ixgbe_txrx_ring_enable(adapter, qid);

		/* Kick start the NAPI context so that receiving will start */
		err = ixgbe_xsk_wakeup(adapter->netdev, qid, XDP_WAKEUP_RX);
		if (err) {
			clear_bit(qid, adapter->af_xdp_zc_qps);
			xsk_pool_dma_unmap(pool, IXGBE_RX_DMA_ATTR);
			return err;
		}
	}

	return 0;
}

static int ixgbe_xsk_pool_disable(struct ixgbe_adapter *adapter, u16 qid)
{
	struct xsk_buff_pool *pool;
	bool if_running;

	pool = xsk_get_pool_from_qid(adapter->netdev, qid);
	if (!pool)
		return -EINVAL;

	if_running = netif_running(adapter->netdev) &&
		     ixgbe_enabled_xdp_adapter(adapter);

	if (if_running)
		ixgbe_txrx_ring_disable(adapter, qid);

	clear_bit(qid, adapter->af_xdp_zc_qps);
	xsk_pool_dma_unmap(pool, IXGBE_RX_DMA_ATTR);

	if (if_running)
		ixgbe_txrx_ring_enable(adapter, qid);

	return 0;
}

int ixgbe_xsk_pool_setup(struct ixgbe_adapter *adapter,
			 struct xsk_buff_pool *pool,
			 u16 qid)
{
	return pool ? ixgbe_xsk_pool_enable(adapter, pool, qid) :
		ixgbe_xsk_pool_disable(adapter, qid);
}

bool ixgbe_alloc_rx_buffers_zc(struct ixgbe_ring *rx_ring, u16 count)
{
	return libie_xg_xsk_alloc_rx_bufs(&rx_ring->base, count);
}

static bool ixgbe_xsk_is_non_eop(struct ixgbe_ring *rx_ring,
				 union ixgbe_adv_rx_desc *rx_desc)
{
	u32 ntc = rx_ring->next_to_clean + 1;

	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;
	rx_ring->pending++;

	prefetch(IXGBE_RX_DESC(rx_ring, ntc));

	if (likely(ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_EOP)))
		return false;

	return true;
}

LIBETH_XDP_DEFINE_START();
LIBETH_XSK_DEFINE_FLUSH_TX(static ixgbe_xsk_flush_tx, ixgbe_prep_xdp_sq,
			   libie_xg_xsk_xmit_desc);
LIBETH_XSK_DEFINE_RUN_PROG(static ixgbe_xsk_run_prog, ixgbe_xsk_flush_tx);
LIBETH_XSK_DEFINE_FINALIZE(static ixgbe_xsk_finalize_xdp_napi,
			   ixgbe_xsk_flush_tx, libie_xg_xdp_rs_and_bump);
LIBETH_XDP_DEFINE_END();

int ixgbe_clean_rx_irq_zc(struct ixgbe_q_vector *q_vector,
			  struct ixgbe_ring *rx_ring,
			  const int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	struct ixgbe_adapter *adapter = q_vector->adapter;
	LIBETH_XDP_ONSTACK_BULK(xdp_tx_bulk);
	struct libeth_xdp_buff *head_xdp;
	bool failure = false;
	struct sk_buff *skb;

	head_xdp = rx_ring->xsk_xdp_head;
	libeth_xsk_tx_init_bulk(&xdp_tx_bulk, rx_ring->xdp_prog,
				adapter->netdev, adapter->xdp_ring,
				adapter->num_xdp_queues);

	while (likely(total_rx_packets < budget)) {
		struct libeth_xdp_buff *rx_buffer;
		union ixgbe_adv_rx_desc *rx_desc;
		unsigned int size;
		u32 xdp_result;

		rx_desc = IXGBE_RX_DESC(rx_ring, rx_ring->next_to_clean);
		size = le16_to_cpu(rx_desc->wb.upper.length);
		if (unlikely(!size))
			break;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * descriptor has been written back
		 */
		dma_rmb();

		rx_buffer = rx_ring->xsk_fqes[rx_ring->next_to_clean];
		head_xdp = libeth_xsk_process_buff(head_xdp, rx_buffer, size);
		if (ixgbe_xsk_is_non_eop(rx_ring, rx_desc) ||
		    unlikely(!head_xdp))
			continue;

		total_rx_packets++;
		total_rx_bytes += xdp_get_buff_len(&head_xdp->base);

		xdp_result = ixgbe_xsk_run_prog(head_xdp, &xdp_tx_bulk);
		if (xdp_result) {
			head_xdp = NULL;
			if (likely(xdp_result != LIBETH_XDP_ABORTED))
				continue;
			failure = true;
			break;
		}

		skb = xdp_build_skb_from_zc(&head_xdp->base);
		if (!skb) {
			libeth_xdp_return_buff_slow(head_xdp);
			head_xdp = NULL;
			rx_ring->rx_stats.alloc_rx_buff_failed++;
			break;
		}

		head_xdp = NULL;

		skb->protocol = eth_type_trans(skb, rx_ring->netdev);
		ixgbe_process_skb_fields(rx_ring, rx_desc, skb);
		ixgbe_rx_skb(q_vector, skb);
	}

	if (rx_ring->pending >= rx_ring->thresh)
		failure |= !ixgbe_alloc_rx_buffers_zc(rx_ring,
						      rx_ring->pending);

	/* place incomplete frames back on ring for completion */
	rx_ring->xsk_xdp_head = head_xdp;

	ixgbe_xsk_finalize_xdp_napi(&xdp_tx_bulk);

	ixgbe_update_rx_ring_stats(rx_ring, q_vector, total_rx_packets,
				   total_rx_bytes);

	if (xsk_uses_need_wakeup(rx_ring->xsk_pool)) {
		if (failure || rx_ring->next_to_clean == rx_ring->next_to_use)
			xsk_set_rx_need_wakeup(rx_ring->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(rx_ring->xsk_pool);

		return (int)total_rx_packets;
	}
	return failure ? budget : (int)total_rx_packets;
}

void ixgbe_xsk_clean_rx_ring(struct ixgbe_ring *rx_ring)
{
	return libie_xg_rx_xsk_ring_free_buffs(&rx_ring->base);
}

bool ixgbe_clean_xdp_tx_irq(struct ixgbe_q_vector *q_vector,
			    struct ixgbe_ring *tx_ring, int napi_budget)
{
	u32 budget = min_t(u32, napi_budget, tx_ring->thresh);

	return libeth_xsk_xmit_do_bulk(tx_ring->xsk_pool, tx_ring, budget,
				       NULL, ixgbe_prep_xdp_sq,
				       libie_xg_xsk_xmit_desc,
				       libie_xg_xdp_rs_and_bump);
}

int ixgbe_xsk_wakeup(struct net_device *dev, u32 qid, u32 flags)
{
	struct ixgbe_adapter *adapter = ixgbe_from_netdev(dev);
	struct ixgbe_ring *ring;

	if (test_bit(__IXGBE_DOWN, &adapter->state))
		return -ENETDOWN;

	if (qid >= adapter->num_xdp_queues)
		return -EINVAL;

	ring = adapter->rx_ring[qid];

	if (unlikely(!ring_is_xsk(ring)))
		return -EINVAL;

	if (!napi_if_scheduled_mark_missed(&ring->q_vector->napi)) {
		u64 eics = BIT_ULL(ring->q_vector->v_idx);

		ixgbe_irq_rearm_queues(adapter, eics);
	}

	return 0;
}
