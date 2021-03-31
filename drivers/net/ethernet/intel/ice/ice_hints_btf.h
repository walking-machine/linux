/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2020, Intel Corporation. */

#ifndef _ICE_HINTS_BTF_H_
#define _ICE_HINTS_BTF_H_

int ice_xdp_register_btfs(struct ice_netdev_priv *priv);
void ice_xdp_unregister_btfs(struct ice_netdev_priv *priv);
int ice_hints_setup(struct btf *btf, char *name, struct btf **supported_btfs);

#endif
