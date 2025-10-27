/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2010-2026 Intel Corporation */

#ifndef _IXGBEVF_TXRX_LIB_H_
#define _IXGBEVF_TXRX_LIB_H_

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

/**
 * ixgbevf_cleanup_headers - Correct corrupted or empty headers
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being fixed
 *
 * Check for corrupted packet headers caused by senders on the local L2
 * embedded NIC switch not setting up their Tx Descriptors right.  These
 * should be very rare.
 *
 * Also address the case where we are pulling data in on pages only
 * and as such no data is present in the skb header.
 *
 * In addition if skb is not at least 60 bytes we need to pad it so that
 * it is large enough to qualify as a valid Ethernet frame.
 *
 * Returns true if an error was encountered and skb was freed.
 **/
static inline bool ixgbevf_cleanup_headers(struct ixgbevf_ring *rx_ring,
					   union ixgbe_adv_rx_desc *rx_desc,
					   struct sk_buff *skb)
{
	/* verify that the packet does not have any known errors */
	if (unlikely(ixgbevf_test_staterr(rx_desc,
					  IXGBE_RXDADV_ERR_FRAME_ERR_MASK))) {
		struct net_device *netdev = rx_ring->netdev;

		if (!(netdev->features & NETIF_F_RXALL)) {
			dev_kfree_skb_any(skb);
			return true;
		}
	}

	return false;
}

#define IXGBE_RSS_L4_TYPES_MASK \
	((1ul << IXGBE_RXDADV_RSSTYPE_IPV4_TCP) | \
	 (1ul << IXGBE_RXDADV_RSSTYPE_IPV4_UDP) | \
	 (1ul << IXGBE_RXDADV_RSSTYPE_IPV6_TCP) | \
	 (1ul << IXGBE_RXDADV_RSSTYPE_IPV6_UDP))

static inline void ixgbevf_rx_hash(struct ixgbevf_ring *ring,
				   union ixgbe_adv_rx_desc *rx_desc,
				   struct sk_buff *skb)
{
	u16 rss_type;

	if (!(ring->netdev->features & NETIF_F_RXHASH))
		return;

	rss_type = le16_to_cpu(rx_desc->wb.lower.lo_dword.hs_rss.pkt_info) &
		   IXGBE_RXDADV_RSSTYPE_MASK;

	if (!rss_type)
		return;

	skb_set_hash(skb, le32_to_cpu(rx_desc->wb.lower.hi_dword.rss),
		     (IXGBE_RSS_L4_TYPES_MASK & (1ul << rss_type)) ?
		     PKT_HASH_TYPE_L4 : PKT_HASH_TYPE_L3);
}

/**
 * ixgbevf_rx_checksum - indicate in skb if hw indicated a good cksum
 * @ring: structure containing ring specific data
 * @rx_desc: current Rx descriptor being processed
 * @skb: skb currently being received and modified
 **/
static inline void ixgbevf_rx_checksum(struct ixgbevf_ring *ring,
				       union ixgbe_adv_rx_desc *rx_desc,
				       struct sk_buff *skb)
{
	skb_checksum_none_assert(skb);

	/* Rx csum disabled */
	if (!(ring->netdev->features & NETIF_F_RXCSUM))
		return;

	/* if IP and error */
	if (ixgbevf_test_staterr(rx_desc, IXGBE_RXD_STAT_IPCS) &&
	    ixgbevf_test_staterr(rx_desc, IXGBE_RXDADV_ERR_IPE)) {
		ring->rx_stats.csum_err++;
		return;
	}

	if (!ixgbevf_test_staterr(rx_desc, IXGBE_RXD_STAT_L4CS))
		return;

	if (ixgbevf_test_staterr(rx_desc, IXGBE_RXDADV_ERR_TCPE)) {
		ring->rx_stats.csum_err++;
		return;
	}

	/* It must be a TCP or UDP packet with a valid checksum */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
}

/**
 * ixgbevf_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being populated
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the checksum, VLAN, protocol, and other fields within
 * the skb.
 **/
static inline void ixgbevf_process_skb_fields(struct ixgbevf_ring *rx_ring,
					      union ixgbe_adv_rx_desc *rx_desc,
					      struct sk_buff *skb)
{
	ixgbevf_rx_hash(rx_ring, rx_desc, skb);
	ixgbevf_rx_checksum(rx_ring, rx_desc, skb);

	if (ixgbevf_test_staterr(rx_desc, IXGBE_RXD_STAT_VP)) {
		u16 vid = le16_to_cpu(rx_desc->wb.upper.vlan);
		unsigned long *active_vlans = netdev_priv(rx_ring->netdev);

		if (test_bit(vid & VLAN_VID_MASK, active_vlans))
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vid);
	}

	if (ixgbevf_test_staterr(rx_desc, IXGBE_RXDADV_STAT_SECP))
		ixgbevf_ipsec_rx(rx_ring, rx_desc, skb);
}

#endif /* _IXGBEVF_TXRX_LIB_H_ */
