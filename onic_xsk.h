/*
 * Copyright (c) 2024 Marco Molè.
 * All rights reserved.
 *
 * This source code is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 */

struct xsk_buff_pool;
struct pci_dev;
int onic_xsk_pool_setup(struct net_device *netdev, struct xsk_buff_pool *pool, u16 qid);
bool onic_xsk_xmit(struct onic_private *priv, struct onic_tx_queue *q);
int onic_run_xdp_zc(struct onic_rx_queue *rx_queue, struct xdp_buff *xdp_buff);
struct sk_buff *onic_xsk_construct_skb(struct napi_struct *napi, struct xdp_buff *xdp);
int onic_xsk_wakeup(struct net_device *dev, u32 qid, u32 flags);
int onic_xsk_pool_enable(struct onic_private *priv, struct xsk_buff_pool *pool, u16 qid);
void onic_queue_pair_disable(struct onic_private *priv, u16 qid);
void onic_queue_pair_enable(struct onic_private *priv, u16 qid);
