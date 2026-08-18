/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Intel Corporation */

#ifndef __IXGBE_DESC_COMMON_H
#define __IXGBE_DESC_COMMON_H

#include <linux/types.h>

/**
 * union ixgbe_adv_rx_desc - Receive Descriptor - Advanced
 * @read: read descriptor
 * @read.pkt_addr: packet buffer address
 * @read.hdr_addr: header buffer address
 * @wb: writeback descriptor
 * @wb.lower: lower 8 bytes
 * @wb.lower.lo_dword: lowest 4 bytes
 * @wb.lower.lo_dword.data: lower 4 bytes
 * @wb.lower.lo_dword.hs_rss: RSS packet type and header split info
 * @wb.lower.lo_dword.hs_rss.pkt_info: RSS Packet Type
 * @wb.lower.lo_dword.hs_rss.hdr_info: header split info
 * @wb.lower.hi_dword: higher 4 bytes of lower 8 bytes
 * @wb.lower.hi_dword.rss: RSS hash
 * @wb.lower.hi_dword.csum_ip: IP ID and packet checksum
 * @wb.lower.hi_dword.csum_ip.ip_id: IP ID
 * @wb.lower.hi_dword.csum_ip.csum: packet checksum
 * @wb.upper: upper 8 bytes
 * @wb.upper.status_error: reported status and errors
 * @wb.upper.length: packet length
 * @wb.upper.vlan: VLAN tag
 */
union ixgbe_adv_rx_desc {
	struct {
		__le64 pkt_addr;
		__le64 hdr_addr;
	} read;
	struct {
		struct {
			union {
				__le32 data;
				struct {
					__le16 pkt_info;
					__le16 hdr_info;
				} hs_rss;
			} lo_dword;
			union {
				__le32 rss;
				struct {
					__le16 ip_id;
					__le16 csum;
				} csum_ip;
			} hi_dword;
		} lower;
		struct {
			__le32 status_error;
			__le16 length;
			__le16 vlan;
		} upper;
	} wb;
};

/**
 * union ixgbe_adv_tx_desc - Transmit Descriptor - Advanced
 * @read: read descriptor
 * @read.buffer_addr: address of the descriptor's data buffer
 * @read.cmd_type_len: length and basic frame flags (EoP, RS, etc.)
 * @read.olinfo_status: per-packet offload information
 * @wb: writeback descriptor
 * @wb.rsvd1: reserved
 * @wb.rsvd2: reserved
 * @wb.status: completion status
 */
union ixgbe_adv_tx_desc {
	struct {
		__le64 buffer_addr;
		__le32 cmd_type_len;
		__le32 olinfo_status;
	} read;
	struct {
		__le64 rsvd1;
		__le32 rsvd2;
		__le32 status;
	} wb;
};

#define IXGBE_TXD_CMD_EOP	0x01000000 /* End of Packet */
#define IXGBE_TXD_CMD_IFCS	0x02000000 /* Insert FCS (Ethernet CRC) */
#define IXGBE_TXD_CMD_RS	0x08000000 /* Report Status */
#define IXGBE_TXD_CMD_DEXT	0x20000000 /* Descriptor ext (0 = legacy) */
#define IXGBE_TXD_STAT_DD	0x00000001 /* Descriptor Done */
#define IXGBE_TXD_CMD		(IXGBE_TXD_CMD_EOP | IXGBE_TXD_CMD_RS)

#define IXGBE_ADVTXD_DTYP_DATA	0x00300000 /* Advanced Data Descriptor */
#define IXGBE_ADVTXD_DCMD_IFCS	IXGBE_TXD_CMD_IFCS /* Insert FCS */
#define IXGBE_ADVTXD_DCMD_DEXT	IXGBE_TXD_CMD_DEXT /* Desc ext (1=Adv) */
#define IXGBE_ADVTXD_CC		0x00000080 /* Check Context */

#define IXGBE_ADVTXD_PAYLEN_SHIFT	14 /* Adv desc PAYLEN shift */

#endif /* __IXGBE_DESC_COMMON_H */
