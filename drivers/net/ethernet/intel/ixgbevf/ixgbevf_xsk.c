#include "ixgbevf_txrx_lib.h"
#include "ixgbevf_xsk.h"
#include <net/libeth/xsk.h>

static void ixgbevf_xsk_xmit_desc(struct libeth_xdp_tx_desc desc, u32 i,
				  const struct libeth_xdpsq *sq, u64 priv)
{
	union ixgbe_adv_tx_desc *tx_desc =
		&((union ixgbe_adv_tx_desc *)sq->descs)[i];

	u32 cmd_type = IXGBE_ADVTXD_DTYP_DATA |
		       IXGBE_ADVTXD_DCMD_DEXT |
		       IXGBE_ADVTXD_DCMD_IFCS |
		       IXGBE_TXD_CMD_EOP |
		       desc.len;

	tx_desc->read.olinfo_status =
		cpu_to_le32((desc.len << IXGBE_ADVTXD_PAYLEN_SHIFT) |
			    IXGBE_ADVTXD_CC);

	tx_desc->read.buffer_addr = cpu_to_le64(desc.addr);
	tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);
}

LIBETH_XDP_DEFINE_START();
LIBETH_XSK_DEFINE_FLUSH_TX(static ixgbevf_xsk_flush_tx, ixgbevf_prep_xdp_sq,
			   ixgbevf_xsk_xmit_desc);
LIBETH_XSK_DEFINE_RUN_PROG(static ixgbevf_xsk_run_prog, ixgbevf_xsk_flush_tx);
LIBETH_XSK_DEFINE_FINALIZE(static ixgbevf_xsk_finalize_xdp_napi,
			   ixgbevf_xsk_flush_tx, ixgbevf_xdp_rs_and_bump);
LIBETH_XDP_DEFINE_END();

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

	while (ntc != rx_ring->next_to_use) {
		xsk_buff_free(&rx_ring->xsk_fqes[ntc]->base);
		ntc++;
		ntc = ntc == rx_ring->count ? 0 : ntc;
	}
}

int ixgbevf_clean_xsk_rx_irq(struct ixgbevf_q_vector *q_vector,
                         struct ixgbevf_ring *rx_ring, int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	struct ixgbevf_adapter *adapter = q_vector->adapter;
	LIBETH_XDP_ONSTACK_BULK(xdp_tx_bulk);
        struct libeth_xdp_buff *head_xdp;
	struct sk_buff *skb;

	head_xdp = rx_ring->xsk_xdp_head;
	libeth_xsk_tx_init_bulk(&xdp_tx_bulk, rx_ring->xdp_prog,
				adapter->netdev, adapter->xdp_ring,
				adapter->num_xdp_queues);

	while (likely(total_rx_packets < budget)) {
		union ixgbe_adv_rx_desc *rx_desc;
		struct libeth_xdp_buff *rx_buffer;
		unsigned int size;

		if (unlikely(rx_ring->pending >= rx_ring->thresh))
			ixgbevf_xsk_alloc_rx_bufs(rx_ring, rx_ring->thresh);

		rx_desc = IXGBEVF_RX_DESC(rx_ring, rx_ring->next_to_clean);
		size = le16_to_cpu(rx_desc->wb.upper.length);
		if (unlikely(!size))
			break;

		rmb();

		rx_buffer = rx_ring->xsk_fqes[rx_ring->next_to_clean];
		head_xdp = libeth_xsk_process_buff(head_xdp, rx_buffer, size);
		if (unlikely(!head_xdp) || ixgbevf_is_non_eop(rx_ring, rx_desc))
			continue;

		if (ixgbevf_xsk_run_prog(head_xdp, &xdp_tx_bulk)) {
			head_xdp = NULL;
			total_rx_packets++;
			total_rx_bytes += size;
			continue;
		}

		skb = xdp_build_skb_from_zc(&head_xdp->base);
		head_xdp = NULL;

		if (unlikely(!skb)) {
			libeth_xdp_return_buff_slow(head_xdp);
			rx_ring->rx_stats.alloc_rx_buff_failed++;
			break;
		}

		if (unlikely(ixgbevf_cleanup_headers(rx_ring, rx_desc, skb))) {
			skb = NULL;
			continue;
		}

		if (unlikely((skb->pkt_type == PACKET_BROADCAST ||
			      skb->pkt_type == PACKET_MULTICAST) &&
			     ether_addr_equal(rx_ring->netdev->dev_addr,
					      eth_hdr(skb)->h_source))) {
			dev_kfree_skb_irq(skb);
			continue;
		}

		/* populate checksum, VLAN, and protocol */
		ixgbevf_process_skb_fields(rx_ring, rx_desc, skb);

		total_rx_bytes += skb->len;
		total_rx_packets++;

		napi_gro_receive(&q_vector->napi, skb);
	}

	/* place incomplete frames back on ring for completion */
	rx_ring->xsk_xdp_head = head_xdp;

	ixgbevf_xsk_finalize_xdp_napi(&xdp_tx_bulk);

	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->stats.packets += total_rx_packets;
	rx_ring->stats.bytes += total_rx_bytes;
	u64_stats_update_end(&rx_ring->syncp);
	q_vector->rx.total_packets += total_rx_packets;
	q_vector->rx.total_bytes += total_rx_bytes;

	return total_rx_packets;
}

bool ixgbevf_clean_xsk_tx_irq(struct ixgbevf_q_vector *q_vector,
                              struct ixgbevf_ring *tx_ring, int napi_budget)
{
	u32 budget = min_t(u32, napi_budget, IXGBEVF_RING_QUARTER(tx_ring));

	return libeth_xsk_xmit_do_bulk(tx_ring->xsk_pool, tx_ring, budget,
				       NULL, ixgbevf_prep_xdp_sq,
				       ixgbevf_xsk_xmit_desc,
				       ixgbevf_xdp_rs_and_bump);
}

int ixgbevf_xsk_wakeup(struct net_device *dev, u32 queue_id, u32 flags)
{
	struct ixgbevf_adapter *adapter = netdev_priv(dev);
	struct ixgbevf_q_vector *q_vector;
	struct ixgbevf_ring *rx_ring;

	if (test_bit(__IXGBEVF_DOWN, &adapter->state))
		return -ENETDOWN;

	if (queue_id >= adapter->num_xdp_queues)
		return -EINVAL;

	rx_ring = adapter->rx_ring[queue_id];
	if (!ring_is_xsk(rx_ring))
		return -EINVAL;

	q_vector = rx_ring->q_vector;
	if (!napi_if_scheduled_mark_missed(&q_vector->napi))
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_VTEICS,
				BIT(q_vector->v_idx));
	//libeth_xsk_wakeup(&rx_ring->xsk_csd, queue_id);

	return 0;
}