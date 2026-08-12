/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 1999 - 2024 Intel Corporation. */

#ifndef _IXGBEVF_DEFINES_H_
#define _IXGBEVF_DEFINES_H_

/* Device IDs */
#define IXGBE_DEV_ID_82599_VF		0x10ED
#define IXGBE_DEV_ID_X540_VF		0x1515
#define IXGBE_DEV_ID_X550_VF		0x1565
#define IXGBE_DEV_ID_X550EM_X_VF	0x15A8
#define IXGBE_DEV_ID_X550EM_A_VF	0x15C5

#define IXGBE_DEV_ID_82599_VF_HV	0x152E
#define IXGBE_DEV_ID_X540_VF_HV		0x1530
#define IXGBE_DEV_ID_X550_VF_HV		0x1564
#define IXGBE_DEV_ID_X550EM_X_VF_HV	0x15A9

#define IXGBE_DEV_ID_E610_VF		0x57AD
#define IXGBE_SUBDEV_ID_E610_VF_HV	0x00FF

#define IXGBE_VF_IRQ_CLEAR_MASK		7
#define IXGBE_VF_MAX_TX_QUEUES		8
#define IXGBE_VF_MAX_RX_QUEUES		8

/* DCB define */
#define IXGBE_VF_MAX_TRAFFIC_CLASS	8

/* Link speed */
typedef u32 ixgbe_link_speed;
#define IXGBE_LINK_SPEED_UNKNOWN	0
#define IXGBE_LINK_SPEED_1GB_FULL	0x0020
#define IXGBE_LINK_SPEED_10GB_FULL	0x0080
#define IXGBE_LINK_SPEED_100_FULL	0x0008

#define IXGBE_CTRL_RST		0x04000000 /* Reset (SW) */
#define IXGBE_RXDCTL_ENABLE	0x02000000 /* Enable specific Rx Queue */
#define IXGBE_TXDCTL_ENABLE	0x02000000 /* Enable specific Tx Queue */
#define IXGBE_LINKS_UP		0x40000000
#define IXGBE_LINKS_SPEED_82599		0x30000000
#define IXGBE_LINKS_SPEED_10G_82599	0x30000000
#define IXGBE_LINKS_SPEED_1G_82599	0x20000000
#define IXGBE_LINKS_SPEED_100_82599	0x10000000

/* Number of Transmit and Receive Descriptors must be a multiple of 8 */
#define IXGBE_REQ_TX_DESCRIPTOR_MULTIPLE	8
#define IXGBE_REQ_RX_DESCRIPTOR_MULTIPLE	8
#define IXGBE_REQ_TX_BUFFER_GRANULARITY		1024

/* Interrupt Vector Allocation Registers */
#define IXGBE_IVAR_ALLOC_VAL	0x80 /* Interrupt Allocation valid */

#define IXGBE_VF_INIT_TIMEOUT	200 /* Number of retries to clear RSTI */

/* Receive Config masks */
#define IXGBE_RXCTRL_RXEN	0x00000001  /* Enable Receiver */
#define IXGBE_RXCTRL_DMBYPS	0x00000002  /* Descriptor Monitor Bypass */
#define IXGBE_RXDCTL_ENABLE	0x02000000  /* Enable specific Rx Queue */
#define IXGBE_RXDCTL_VME	0x40000000  /* VLAN mode enable */
#define IXGBE_RXDCTL_RLPMLMASK	0x00003FFF  /* Only supported on the X540 */
#define IXGBE_RXDCTL_RLPML_EN	0x00008000

/* DCA Control */
#define IXGBE_DCA_TXCTRL_TX_WB_RO_EN BIT(11) /* Tx Desc writeback RO bit */

/* PSRTYPE bit definitions */
#define IXGBE_PSRTYPE_TCPHDR	0x00000010
#define IXGBE_PSRTYPE_UDPHDR	0x00000020
#define IXGBE_PSRTYPE_IPV4HDR	0x00000100
#define IXGBE_PSRTYPE_IPV6HDR	0x00000200
#define IXGBE_PSRTYPE_L2HDR	0x00001000

/* SRRCTL bit definitions */
#define IXGBE_SRRCTL_BSIZEPKT_STEP	1024
#define IXGBE_SRRCTL_RDMTS_SHIFT	22
#define IXGBE_SRRCTL_RDMTS_MASK		0x01C00000
#define IXGBE_SRRCTL_DROP_EN		0x10000000
#define IXGBE_SRRCTL_BSIZEPKT_MASK	0x0000007F
#define IXGBE_SRRCTL_BSIZEHDR_MASK	0x00003F00
#define IXGBE_SRRCTL_DESCTYPE_LEGACY	0x00000000
#define IXGBE_SRRCTL_DESCTYPE_ADV_ONEBUF 0x02000000
#define IXGBE_SRRCTL_DESCTYPE_HDR_SPLIT	0x04000000
#define IXGBE_SRRCTL_DESCTYPE_HDR_REPLICATION_LARGE_PKT 0x08000000
#define IXGBE_SRRCTL_DESCTYPE_HDR_SPLIT_ALWAYS 0x0A000000
#define IXGBE_SRRCTL_DESCTYPE_MASK	0x0E000000

/* Interrupt register bitmasks */

#define IXGBE_EITR_CNT_WDIS	0x80000000
#define IXGBE_MAX_EITR		0x00000FF8
#define IXGBE_MIN_EITR		8

/* Error Codes */
#define IXGBE_ERR_INVALID_MAC_ADDR	-1
#define IXGBE_ERR_RESET_FAILED		-2
#define IXGBE_ERR_INVALID_ARGUMENT	-3
#define IXGBE_ERR_CONFIG		-4
#define IXGBE_ERR_MBX			-5
#define IXGBE_ERR_TIMEOUT		-6
#define IXGBE_ERR_PARAM			-7

/* Transmit Config masks */
#define IXGBE_TXDCTL_ENABLE		0x02000000 /* Ena specific Tx Queue */
#define IXGBE_TXDCTL_SWFLSH		0x04000000 /* Tx Desc. wr-bk flushing */
#define IXGBE_TXDCTL_WTHRESH_SHIFT	16	   /* shift to WTHRESH bits */

#define IXGBE_DCA_RXCTRL_DESC_DCA_EN	BIT(5)  /* Rx Desc enable */
#define IXGBE_DCA_RXCTRL_HEAD_DCA_EN	BIT(6)  /* Rx Desc header ena */
#define IXGBE_DCA_RXCTRL_DATA_DCA_EN	BIT(7)  /* Rx Desc payload ena */
#define IXGBE_DCA_RXCTRL_DESC_RRO_EN	BIT(9)  /* Rx rd Desc Relax Order */
#define IXGBE_DCA_RXCTRL_DATA_WRO_EN	BIT(13) /* Rx wr data Relax Order */
#define IXGBE_DCA_RXCTRL_HEAD_WRO_EN	BIT(15) /* Rx wr header RO */

#define IXGBE_DCA_TXCTRL_DESC_DCA_EN	BIT(5)  /* DCA Tx Desc enable */
#define IXGBE_DCA_TXCTRL_DESC_RRO_EN	BIT(9)  /* Tx rd Desc Relax Order */
#define IXGBE_DCA_TXCTRL_DESC_WRO_EN	BIT(11) /* Tx Desc writeback RO bit */
#define IXGBE_DCA_TXCTRL_DATA_RRO_EN	BIT(13) /* Tx rd data Relax Order */

#endif /* _IXGBEVF_DEFINES_H_ */
