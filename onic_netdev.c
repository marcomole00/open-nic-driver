/*
 * Copyright (c) 2020 Xilinx, Inc.
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
#include <linux/if_link.h>
#include <linux/pci_regs.h>
#include <linux/version.h>
#include <linux/pci.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/bpf_trace.h>
#include <net/page_pool.h>
#include <net/xdp_sock_drv.h>
#include <net/xsk_buff_pool.h>

#include "onic_netdev.h"
#include "onic_hardware.h"
#include "qdma_access/qdma_register.h"
#include "onic.h"
#include "onic_xsk.h"
#include "xclbin.h"

#define ONIC_RX_DESC_STEP 256

inline u16 onic_ring_get_real_count(struct onic_ring *ring)
{
	/* Valid writeback entry means one less count of descriptor entries */
	return (ring->wb) ? (ring->count - 1) : ring->count;
}

inline  bool onic_ring_full(struct onic_ring *ring)
{
	u16 real_count = onic_ring_get_real_count(ring);
	return ((ring->next_to_use + 1) % real_count) == ring->next_to_clean;
}

inline  void onic_ring_increment_head(struct onic_ring *ring)
{
	u16 real_count = onic_ring_get_real_count(ring);
	ring->next_to_use = (ring->next_to_use + 1) % real_count;
}

inline  void onic_ring_increment_tail(struct onic_ring *ring)
{
	u16 real_count = onic_ring_get_real_count(ring);
	ring->next_to_clean = (ring->next_to_clean + 1) % real_count;
}

void onic_tx_clean(struct onic_tx_queue *q) {
  struct onic_private *priv = netdev_priv(q->netdev);
  struct onic_ring *ring = &q->ring;
  struct qdma_wb_stat wb;
  int work, i,xsk_trasmitted = 0;

  // this is a locking mechanism to guarantee that only one thread is cleaning
  // the ring bitmask functions are atomic!
  if (test_and_set_bit(0, q->state))
    return;

  qdma_unpack_wb_stat(&wb, ring->wb);

  if (wb.cidx == ring->next_to_clean) {
    clear_bit(0, q->state);
    return;
  }

  work = wb.cidx - ring->next_to_clean;
  if (work < 0)
    work += onic_ring_get_real_count(ring);

  for (i = 0; i < work; ++i) {
    struct onic_tx_buffer *buf = &q->buffer[ring->next_to_clean];

    if (buf->type == ONIC_TX_SKB) {
      // The packet originated from the kernel network stack
      dma_unmap_single(&priv->pdev->dev, buf->dma_addr, buf->len,
                       DMA_TO_DEVICE);
      dev_kfree_skb_any(buf->skb);
      buf->skb = NULL;
    } else if (buf->type == ONIC_TX_XDPF) {
      // The packet originated from a XDP_TX -> It comes from a page pool, no
      // need to dma unmap
      xdp_return_frame(buf->xdpf);
      buf->xdpf = NULL;
    } else if (buf->type == ONIC_TX_XDPF_XMIT) {
      // The packet originated from the XDP program of another driver.
      // It was mapped to a DMA address and needs to be unmapped
      dma_unmap_single(&priv->pdev->dev, buf->dma_addr, buf->len,
                       DMA_TO_DEVICE);
      xdp_return_frame(buf->xdpf);
      buf->xdpf = NULL;
    } else if (buf->type == ONIC_TX_XSK) {
      xsk_trasmitted++;
    } else {
      netdev_err(priv->netdev, "unknown buffer type %d\n", buf->type);
    }

    onic_ring_increment_tail(ring);
  }
  if (xsk_trasmitted)
    xsk_tx_completed(q->xsk_pool, xsk_trasmitted);

  clear_bit(0, q->state);
}


static void onic_update_tx_need_wakeup(struct onic_tx_queue *q, bool wake_up){

  if (q->xsk_pool && xsk_uses_need_wakeup(q->xsk_pool)) {
    if (wake_up)
      xsk_set_tx_need_wakeup(q->xsk_pool);
    else
      xsk_clear_tx_need_wakeup(q->xsk_pool);
  }
	
}

// static bool onic_rx_high_watermark(struct onic_rx_queue *q)
// {
// 	struct onic_ring *ring = &q->desc_ring;
// 	int unused;

// 	unused = ring->next_to_use - ring->next_to_clean;
// 	if (ring->next_to_use < ring->next_to_clean)
// 		unused += onic_ring_get_real_count(ring);

// 	return (unused < (ONIC_RX_DESC_STEP / 2));
// }


// static int onic_unused_desc(struct onic_rx_queue *q)
// {
// 	struct onic_ring *ring = &q->desc_ring;
// 	int unused;

// 	unused = ring->next_to_clean - ring->next_to_use;
// 	if (ring->next_to_use < ring->next_to_clean)
// 		unused += onic_ring_get_real_count(ring);

// 	return unused;
// }



static int onic_rx_pp_refill(struct onic_rx_queue *q, int budget)
{

	struct onic_private *priv = netdev_priv(q->netdev);
	struct onic_ring *desc_ring = &q->desc_ring;
	struct qdma_c2h_st_desc desc;

	int i = 0;
	for (i = 0; i < budget; i++) {
		u8 *desc_ptr =
		    desc_ring->desc + QDMA_C2H_ST_DESC_SIZE * desc_ring->next_to_use;
		struct page *pg;

		pg = page_pool_dev_alloc_pages(q->page_pool);
		if (!pg) {
			netdev_err(priv->netdev, "page_pool_dev_alloc_pages failed\n");
			break;
		}

		q->buffer[desc_ring->next_to_use].pg = pg;
		q->buffer[desc_ring->next_to_use].offset = XDP_PACKET_HEADROOM;

		desc.dst_addr = page_pool_get_dma_addr(pg) + XDP_PACKET_HEADROOM;

		qdma_pack_c2h_st_desc(desc_ptr, &desc);
		onic_ring_increment_head(desc_ring);
	}

	// netdev_info(priv->netdev, "%s: allocated %d buffers, ntc %d ntu %d", __func__, buffers_allocated, desc_ring->next_to_clean, desc_ring->next_to_use);
	// onic_set_rx_head(priv->hw.qdma, q->qid, desc_ring->next_to_use);
	// head will be moved at the end of the napi poll
	return i;

}

static int onic_rx_zc_refill(struct onic_rx_queue *q, int budget)
{

	struct onic_ring *desc_ring = &q->desc_ring;
	struct qdma_c2h_st_desc desc;
	int i = 0;
	bool wake_up = false;

	
	for (i = 0; i < budget; i++) {
		u8 *desc_ptr =
		    desc_ring->desc + QDMA_C2H_ST_DESC_SIZE * desc_ring->next_to_use;
		struct xdp_buff *xdp_buff;
		xdp_buff = xsk_buff_alloc(q->xsk_pool);
		if (!xdp_buff) {
			netdev_err(q->netdev, "xsk_buff_alloc failed\n");
			wake_up = true;
			break;
		}
		q->xdps[desc_ring->next_to_use] = xdp_buff;
		desc.dst_addr = xsk_buff_xdp_get_dma(xdp_buff);

		qdma_pack_c2h_st_desc(desc_ptr, &desc);
		onic_ring_increment_head(desc_ring);
	}

	// netdev_info(priv->netdev, "%s: allocated %d buffers, ntc %d ntu %d", __func__, buffers_allocated, desc_ring->next_to_clean, desc_ring->next_to_use);
	// onic_set_rx_head(priv->hw.qdma, q->qid, desc_ring->next_to_use);
	if (likely(q->xsk_pool) && xsk_uses_need_wakeup(q->xsk_pool)) {
		if (wake_up)
			xsk_set_rx_need_wakeup(q->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(q->xsk_pool);
	}

	return i;
}

// static bool onic_rx_refill(struct onic_rx_queue *q) {
//   struct onic_private *priv = netdev_priv(q->netdev);
//   struct onic_ring *desc_ring = &q->desc_ring;
//   struct qdma_c2h_st_desc desc;
//   int i = 0;
//   int buffers_allocated = 0;
//   bool wake_up = false;

//   // netdev_info(priv->netdev, "%s @ q#%d  ntc %d ntu %d", __func__,
//               // q->qid,desc_ring->next_to_clean, desc_ring->next_to_use);
//   // the upper bound should be min(ONIX_RX_DESC_STEP, NTU-NTC)?
//   //TODO: tweak this this parameter to see if there are differences
//   for (i = 0; i < ONIC_RX_DESC_STEP; i++)

//   {
// 		u8 *desc_ptr =
// 		    desc_ring->desc + QDMA_C2H_ST_DESC_SIZE * desc_ring->next_to_use;
//     if (q->xsk_pool) {
//       struct xdp_buff *xdp_buff;
//       xdp_buff = xsk_buff_alloc(q->xsk_pool);
//       if (!xdp_buff) {
//         netdev_err(q->netdev, "xsk_buff_alloc failed\n");
//         wake_up = true;
//         break;
//       }
//       buffers_allocated++;
//       q->xdps[desc_ring->next_to_use] = xdp_buff;
//       desc.dst_addr = xsk_buff_xdp_get_dma(xdp_buff);
//     } else {
//       struct page *pg;
//       pg = page_pool_dev_alloc_pages(q->page_pool);
//       if (!pg) {
//         netdev_err(q->netdev, "page_pool_dev_alloc_pages failed\n");
//         break;
//       }

//       buffers_allocated++;
//       q->buffer[desc_ring->next_to_use].pg = pg;
//       q->buffer[desc_ring->next_to_use].offset = XDP_PACKET_HEADROOM;

//       desc.dst_addr = page_pool_get_dma_addr(pg) + XDP_PACKET_HEADROOM;
//     }

//     qdma_pack_c2h_st_desc(desc_ptr, &desc);
//     onic_ring_increment_head(desc_ring);
//   }

// 	// netdev_info(priv->netdev, "%s: allocated %d buffers, ntc %d ntu %d", __func__, buffers_allocated, desc_ring->next_to_clean, desc_ring->next_to_use);
//   onic_set_rx_head(priv->hw.qdma, q->qid, desc_ring->next_to_use);

//   if (q->xsk_pool) {
//     if (!xsk_uses_need_wakeup(q->xsk_pool))
//       return wake_up; // signal to the outer function to not call
//                       // napi_complete_done, because we have to reschedule
//     if (wake_up)
//       xsk_set_rx_need_wakeup(q->xsk_pool);
//     else
//       xsk_clear_rx_need_wakeup(q->xsk_pool);
//   }
//   return false;
//   }

static struct onic_tx_queue *onic_xdp_tx_queue_mapping(struct onic_private *priv)
{
	unsigned int r_idx = smp_processor_id();

	if (r_idx >= priv->num_tx_queues)
		r_idx = r_idx % priv->num_tx_queues;

	return priv->tx_queue[r_idx];
}

static int onic_xmit_xdp_ring(struct onic_private *priv,struct  onic_tx_queue  *tx_queue, struct xdp_frame *xdpf, bool dma_map)
 {
	u8 *desc_ptr;
	dma_addr_t dma_addr;
	struct onic_ring *ring;
	struct qdma_h2c_st_desc desc;
	bool debug = 1;
	struct rtnl_link_stats64 *pcpu_stats_pointer;
	enum onic_tx_buf_type type;

	ring = &tx_queue->ring;
	
	onic_tx_clean(tx_queue);

	if (onic_ring_full(ring)) {
		if (debug)
			netdev_info(priv->netdev, "ring is full");
		return NETDEV_TX_BUSY;
	}

	if (dma_map) {
		/* ndo_xdp_dmit */
		dma_addr = dma_map_single(&priv->pdev->dev, xdpf->data,xdpf->len, DMA_TO_DEVICE);
		type = ONIC_TX_XDPF_XMIT;
		if (unlikely(dma_mapping_error(&priv->pdev->dev, dma_addr)))
			return ONIC_XDP_CONSUMED;
	} else {
		/* ONIC_XDP_TX */
		struct page *page = virt_to_page(xdpf->data);
		dma_addr = page_pool_get_dma_addr(page) + sizeof(*xdpf) + xdpf->headroom;
		dma_sync_single_for_device(&priv->pdev->dev, dma_addr,
					   xdpf->len, DMA_BIDIRECTIONAL);
		type = ONIC_TX_XDPF;
		
	}

	

	desc_ptr = ring->desc + QDMA_H2C_ST_DESC_SIZE * ring->next_to_use;
	desc.len = xdpf->len;
	desc.src_addr = dma_addr;
	desc.metadata = xdpf->len;
	qdma_pack_h2c_st_desc(desc_ptr, &desc);

	tx_queue->buffer[ring->next_to_use].xdpf = xdpf;
	tx_queue->buffer[ring->next_to_use].type = type;
	tx_queue->buffer[ring->next_to_use].dma_addr = dma_addr;
	tx_queue->buffer[ring->next_to_use].len = xdpf->len;
	

  	pcpu_stats_pointer = this_cpu_ptr(priv->netdev_stats);
  	pcpu_stats_pointer->tx_packets++;
	pcpu_stats_pointer->tx_bytes += xdpf->len;
	onic_ring_increment_head(ring);

	// This gets called only if version is >= 5.3.0 since we do not support
	// TX/REDIR on older versions
	

	return ONIC_XDP_TX;
}

int onic_xdp_xmit_back(struct onic_rx_queue *q, struct xdp_buff *xdp_buff) {
	struct onic_private *priv = netdev_priv(q->netdev);
	struct xdp_frame *xdpf = xdp_convert_buff_to_frame(xdp_buff);
	struct onic_tx_queue *tx_queue;
	struct netdev_queue *nq;
	u32 ret = 0, cpu = smp_processor_id();
	bool dma_map = false;

	if (q->xsk_pool){
		dma_map = true;
	}

	if (unlikely(!xdpf)){
		q->xdp_rx_stats.xdp_tx_err++;
		return ONIC_XDP_CONSUMED;
	}

	tx_queue = q->xdp_prog ? priv->tx_queue[q->qid] : NULL;
	if (unlikely(!tx_queue)){
		q->xdp_rx_stats.xdp_tx_err++;
		return -ENXIO;
	}

	nq = netdev_get_tx_queue(tx_queue->netdev, tx_queue->qid);

	__netif_tx_lock(nq, cpu);
	ret = onic_xmit_xdp_ring(priv, tx_queue, xdpf,dma_map);
	q->xdp_rx_stats.xdp_tx++;

	wmb();
	onic_set_tx_head(priv->hw.qdma, tx_queue->qid, tx_queue->ring.next_to_use);

	__netif_tx_unlock(nq);

	return ret;
}

static void *onic_run_xdp(struct onic_rx_queue *rx_queue, struct xdp_buff *xdp_buff) {
	int err, result = ONIC_XDP_PASS;
	struct bpf_prog *xdp_prog;
	u32 act;
	struct page *page = virt_to_page(xdp_buff->data_hard_start);
	
	xdp_prog = rx_queue->xdp_prog;
	if (!xdp_prog){
		goto out;
	}

	act = bpf_prog_run_xdp(xdp_prog, xdp_buff);
	
	switch (act){
		case XDP_PASS:
			rx_queue->xdp_rx_stats.xdp_pass++;
			break;
// Since before 5.3.0 the xmit_more hint was tied to skbs, and in XDP we run
// before skb allocation, we cannot correctly implement onic_xdp_xmit_frame and
// thus XDP_TX and XDP_REDIRECT
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
    case XDP_TX:
			result = onic_xdp_xmit_back(rx_queue, xdp_buff);
			if (result == ONIC_XDP_CONSUMED) {
				goto out_failure;
				}
			break;
    case XDP_REDIRECT:
			err = xdp_do_redirect(rx_queue->netdev, xdp_buff, xdp_prog);
			if (err) {
				result = ONIC_XDP_CONSUMED;
				goto out_failure;
			}
			result = ONIC_XDP_REDIR;
			rx_queue->xdp_rx_stats.xdp_redirect++;
			break;
#elif defined(RHEL_RELEASE_CODE)
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 1))
    case XDP_TX:
			result = onic_xdp_xmit_back(rx_queue, xdp_buff);
			if (result == ONIC_XDP_CONSUMED)
				goto out_failure;
			break;
    case XDP_REDIRECT:
			err = xdp_do_redirect(rx_queue->netdev, xdp_buff, xdp_prog);
			if (err) {
				ret = ONIC_XDP_CONSUMED;
				goto out_failure;
			}
			result = ONIC_XDP_REDIR;
			rx_queue->xdp_rx_stats.xdp_redirect++;
			break;
#endif
#else
		case XDP_TX:
			fallthrough;
		case XDP_REDIRECT
			fallthrough;
#endif
    default:
			bpf_warn_invalid_xdp_action(act);
			fallthrough;
    case XDP_ABORTED:
out_failure:
		/* my reference implementation of xdp_stats was the mvneta driver and it does not track XDP_ABORTED events*/
		/* by themselves and groups them in XDP_DROP stats.*/
			trace_xdp_exception(rx_queue->netdev, xdp_prog, act);
			fallthrough;
    case XDP_DROP:
			result = ONIC_XDP_CONSUMED;
			rx_queue->xdp_rx_stats.xdp_drop++;
			page_pool_recycle_direct(rx_queue->page_pool, page);
			break;
  }

out:
	return ERR_PTR(-result);
}

// static int onic_rx_poll(struct napi_struct *napi, int budget) {
//   struct onic_rx_queue *q = container_of(napi, struct onic_rx_queue, napi);
//   struct onic_private *priv = netdev_priv(q->netdev);
//   u16 qid = q->qid;
//   struct onic_ring *desc_ring = &q->desc_ring;
//   struct onic_ring *cmpl_ring = &q->cmpl_ring;
//   struct qdma_c2h_cmpl cmpl;
//   struct qdma_c2h_cmpl_stat cmpl_stat;
//   u8 *cmpl_ptr;
//   u8 *cmpl_stat_ptr;
//   u32 color_stat;
//   int work = 0;
//   int i, rv, err;
//   bool napi_cmpl_rval = 0;
//   bool flipped = 0;
//   bool debug = 0;
//   void *res;
//   bool alloc_err_xsk = false;
//   bool tx_wake;

//   struct xdp_buff xdp;
//   unsigned int xdp_xmit = 0;
//   struct rtnl_link_stats64 *pcpu_stats_pointer;
//   pcpu_stats_pointer = this_cpu_ptr(priv->netdev_stats);

//   if (debug)
//     netdev_info(q->netdev, "%s qid %d", __func__, qid);


//   cmpl_ptr = cmpl_ring->desc + QDMA_C2H_CMPL_SIZE * cmpl_ring->next_to_clean;
//   cmpl_stat_ptr = cmpl_ring->desc + QDMA_C2H_CMPL_SIZE * (cmpl_ring->count - 1);

//   qdma_unpack_c2h_cmpl(&cmpl, cmpl_ptr);
//   qdma_unpack_c2h_cmpl_stat(&cmpl_stat, cmpl_stat_ptr);

//   color_stat = cmpl_stat.color;
//   if (debug)
//     netdev_info(q->netdev,
//                 "\n rx_poll:  cmpl_stat_pidx %u, color_cmpl_stat %u, cmpl_ring "
//                 "next_to_clean %u, cmpl_stat_cidx %u, intr_state %u, "
//                 "cmpl_ring->count %u",
//                 cmpl_stat.pidx, color_stat, cmpl_ring->next_to_clean,
//                 cmpl_stat.cidx, cmpl_stat.intr_state, cmpl_ring->count);

//   if (debug)
//     netdev_info(q->netdev,
//                 "c2h_cmpl pkt_id %u, pkt_len %u, error %u, color %u "
//                 "cmpl_ring->color:%u",
//                 cmpl.pkt_id, cmpl.pkt_len, cmpl.err, cmpl.color,
//                 cmpl_ring->color);

//   /* Color of completion entries and completion ring are initialized to 0
//    * and 1 respectively.  When an entry is filled, it has a color bit of
//    * 1, thus making it the same as the completion ring color.  A different
//    * color indicates that we are done with the current batch.  When the
//    * ring index wraps around, the color flips in both software and
//    * hardware.  Therefore, it becomes that completion entries are filled
//    * with a color 0, and completion ring has a color 0 as well.
//    */
//   if (cmpl.color != cmpl_ring->color) {
//     if (debug)
//       netdev_info(q->netdev,
//                   "color mismatch1: cmpl.color %u, cmpl_ring->color %u  "
//                   "cmpl_stat_color %u",
//                   cmpl.color, cmpl_ring->color, color_stat);
//   }

//   if (cmpl.err == 1) {
//     if (debug)
//       netdev_info(q->netdev, "completion error detected in cmpl entry!");
//     // todo: need to handle the error ...
//     onic_qdma_clear_error_interrupt(priv->hw.qdma);
//   }

//   // main processing loop for rx_poll
//   while ((cmpl_ring->next_to_clean != cmpl_stat.pidx)) {

//     struct sk_buff *skb;
//     int xdp_result;

//     int len = cmpl.pkt_len;

//     if (!!q->xsk_pool != !!test_bit(qid, priv->af_xdp_zc_qps)) {
//       netdev_err(q->netdev, "xsk_pool and af_xdp_zc_qps are not in sync");
//     }

//     if (q->xsk_pool && test_bit(qid, priv->af_xdp_zc_qps)) {

//       struct xdp_buff *xdp_buff = q->xdps[desc_ring->next_to_clean];
//       if (!q->xdp_prog) {
//         netdev_err(q->netdev,
//                    "XSK pool is present with no XDP program. No further packet "
//                    "will be processed as this is a transient state");
//         break;
//       }
//       // todo copy from consume_zc
//       xdp_buff->data_end = xdp_buff->data + len;
//       xsk_buff_dma_sync_for_cpu(xdp_buff, q->xsk_pool);
//       xdp_result = onic_run_xdp_zc(q, xdp_buff);
//       xdp_xmit |= xdp_result;
//       if (xdp_result == ONIC_XDP_CONSUMED) {
//         xsk_buff_free(xdp_buff);
//       } else if (xdp_result == ONIC_XDP_PASS) {
//         skb = onic_xsk_construct_skb(napi, xdp_buff);
//         if (skb) {
//           skb_record_rx_queue(skb, q->qid);
//           skb->protocol = eth_type_trans(skb, q->netdev);
//           err = napi_gro_receive(napi, skb);
//           if (err < 0) {
//             netdev_err(q->netdev, "napi_gro_receive, err = %d", rv);
//           }
//         }
//         xsk_buff_free(xdp_buff);
//       }
//     } else {
//       struct onic_rx_buffer *buf = &q->buffer[desc_ring->next_to_clean];
//       xdp_init_buff(&xdp, PAGE_SIZE, &q->xdp_rxq);

//       dma_sync_single_for_cpu(&priv->pdev->dev,
//                               page_pool_get_dma_addr(buf->pg) + buf->offset,
//                               len, DMA_FROM_DEVICE);

//       xdp_prepare_buff(&xdp, page_address(buf->pg), buf->offset, len, false);

//       res = onic_run_xdp(q, &xdp);
//       if (IS_ERR(res)) {
//         unsigned int xdp_res = -PTR_ERR(res);

//         if (xdp_res & (ONIC_XDP_TX | ONIC_XDP_REDIR)) {
//           xdp_xmit |= xdp_res;
//         }

//         // Allocate skb only if we are continuing to process the packet
//         if (xdp_res & ONIC_XDP_PASS) {

//           // allocate a new skb structure around the data
//           skb = napi_build_skb(xdp.data_hard_start, PAGE_SIZE);

//           if (!skb) {
//             rv = -ENOMEM;
//             break;
//           }

//           // mark the skb for page_pool recycling
//           skb_mark_for_recycle(skb);
//           // reserve space in the skb for the data for the xdp headroom
//           skb_reserve(skb, xdp.data - xdp.data_hard_start);
//           // set the data pointer
//           skb_put(skb, xdp.data_end - xdp.data);

//           skb->protocol = eth_type_trans(skb, q->netdev);
//           skb->ip_summed = CHECKSUM_NONE;
//           skb_record_rx_queue(skb, qid);
//           rv = napi_gro_receive(napi, skb);
//           if (rv < 0) {
//             netdev_err(q->netdev, "napi_gro_receive, err = %d", rv);
//             break;
//           }
//         }
//       }
//     }

//     pcpu_stats_pointer->rx_packets++;
//     pcpu_stats_pointer->rx_bytes += len;

//     onic_ring_increment_tail(desc_ring);

//     if (debug)
//       netdev_info(q->netdev, "desc_ring %u next_to_use:%u next_to_clean:%u",
//                   onic_ring_get_real_count(desc_ring), desc_ring->next_to_use,
//                   desc_ring->next_to_clean);
//     if (onic_ring_full(desc_ring)) {
//       netdev_dbg(q->netdev, "desc_ring full");
//     }

//     if (onic_rx_high_watermark(q)) {
//       netdev_dbg(q->netdev, "High watermark: h = %d, t = %d",
//                  desc_ring->next_to_use, desc_ring->next_to_clean);
//       alloc_err_xsk = onic_rx_refill(q);
//     }

//     onic_ring_increment_tail(cmpl_ring);

//     if (debug)
//       netdev_info(q->netdev,
//                   "cmpl_ring %u next_to_use:%u next_to_clean:%u, flipped:%s",
//                   onic_ring_get_real_count(cmpl_ring), cmpl_ring->next_to_use,
//                   cmpl_ring->next_to_clean, flipped ? "true" : "false");
//     if (onic_ring_full(cmpl_ring)) {
//       netdev_dbg(q->netdev, "cmpl_ring full");
//     }
//     if (cmpl.color != cmpl_ring->color) {
//       if (debug)
//         netdev_info(q->netdev,
//                     "part 1. cmpl_ring->next_to_clean=%u color *** old fliping "
//                     "*** color[%u]",
//                     cmpl_ring->next_to_clean, cmpl_ring->color);
//       cmpl_ring->color = (cmpl_ring->color == 0) ? 1 : 0;
//       flipped = 1;
//     }
//     cmpl_ptr =
//         cmpl_ring->desc + (QDMA_C2H_CMPL_SIZE * cmpl_ring->next_to_clean);

//     if ((++work) >= budget) {
//       if (xdp_xmit & ONIC_XDP_REDIR)
//         xdp_do_flush();
//       if (debug)
//         netdev_info(q->netdev, "watchdog work %u, budget %u", work, budget);
//       // napi_complete(napi);
//       // napi_reschedule(napi);
//       goto out_of_budget;
//     }

//     qdma_unpack_c2h_cmpl(&cmpl, cmpl_ptr);

//     if (debug)
//       netdev_info(q->netdev,
//                   "c2h_cmpl(b) pkt_id %u, pkt_len %u, error %u, color %u",
//                   cmpl.pkt_id, cmpl.pkt_len, cmpl.err, cmpl.color);
//   }

//   if (onic_rx_high_watermark(q)) {
//     netdev_dbg(q->netdev, "High watermark: h = %d, t = %d",
//                desc_ring->next_to_use, desc_ring->next_to_clean);
//     alloc_err_xsk = onic_rx_refill(q);
//   }
//   if (xdp_xmit & ONIC_XDP_REDIR)
//     xdp_do_flush();

//   napi_cmpl_rval = napi_complete_done(napi, work);

//   onic_set_completion_tail(priv->hw.qdma, qid, cmpl_ring->next_to_clean,
//                            napi_cmpl_rval);

//   if (q->xsk_pool) {
//     if (!xsk_uses_need_wakeup(q->xsk_pool) && alloc_err_xsk)
//     // if the pool is not using wake up and the fill ring is empty : reschedule
//       return budget;
//   }
// out_of_budget:
//   if (debug)
//     netdev_info(q->netdev, "rx_poll is done");
//   if (debug)
//     netdev_info(
//         q->netdev, "rx_poll returning work %u, rx_packets %lld, rx_bytes %lld",
//         work, pcpu_stats_pointer->rx_packets, pcpu_stats_pointer->rx_bytes);
//   return work;
// }



int onic_ring_get_occupancy(struct onic_ring *ring) {
	int ntc = ring->next_to_clean;
	int ntu = ring->next_to_use;
	
	return ntu >= ntc ? ntu - ntc : ntu - ntc + onic_ring_get_real_count(ring);
}
void onic_clear_tx_queue(struct onic_private *priv, u16 qid)
{
	struct onic_tx_queue *q = priv->tx_queue[qid];
	struct onic_ring *ring;
	u32 size;
	int real_count;
	int i;


	if (!q)
		return;

	onic_tx_clean(q);

	onic_qdma_clear_tx_queue(priv->hw.qdma, qid);

	ring = &q->ring;
	real_count = ring->count - 1;
	size = QDMA_H2C_ST_DESC_SIZE * real_count + QDMA_WB_STAT_SIZE;
	size = ALIGN(size, PAGE_SIZE);
	netdev_info(q->netdev, "Cleaning QTX #%d ntc %d ntu %d distance=%d",q->qid, ring->next_to_clean, ring->next_to_use, onic_ring_get_occupancy(ring));
	
	for (i = 0; i < real_count; ++i) {
		if ((q->buffer[i].type & ONIC_TX_SKB ) && q->buffer[i].skb) {
			netdev_err(priv->netdev, "Weird, skb is not NULL\n");
		} else if ((q->buffer[i].type & (ONIC_TX_XDPF || ONIC_TX_XDPF_XMIT)) && q->buffer[i].xdpf) {
			netdev_err(priv->netdev, "Weird, skb is not NULL\n");
		}
	}

	if (ring->desc)
		dma_free_coherent(&priv->pdev->dev, size, ring->desc,
				  ring->dma_addr);
	if (q->buffer) kfree(q->buffer);
	kfree(q);
	priv->tx_queue[qid] = NULL;
}

 int onic_init_tx_queue(struct onic_private *priv, u16 qid)
{
	const u8 rngcnt_idx = 0;
	struct net_device *dev = priv->netdev;
	struct onic_tx_queue *q;
	struct onic_ring *ring;
	struct onic_qdma_h2c_param param;
	u16 vid;
	u32 size, real_count;
	int rv;
	bool debug = 0;

	if (priv->tx_queue[qid]) {
		if (debug)
			netdev_info(dev, "Re-initializing TX queue %d", qid);
		onic_clear_tx_queue(priv, qid);
	}

	q = kzalloc(sizeof(struct onic_tx_queue), GFP_KERNEL);
	if (!q)
		return -ENOMEM;

	/* evenly assign to TX queues available vectors */
	vid = qid % priv->num_q_vectors;

	q->netdev = dev;
	q->vector = priv->q_vector[vid];
	q->qid = qid;

	ring = &q->ring;
	ring->count = onic_ring_count(rngcnt_idx);
	real_count = ring->count - 1;

	/* allocate DMA memory for TX descriptor ring */
	size = QDMA_H2C_ST_DESC_SIZE * real_count + QDMA_WB_STAT_SIZE;
	size = ALIGN(size, PAGE_SIZE);
	ring->desc = dma_alloc_coherent(&priv->pdev->dev, size, &ring->dma_addr,
					GFP_KERNEL);
	if (!ring->desc) {
		rv = -ENOMEM;
		goto clear_tx_queue;
	}
	memset(ring->desc, 0, size);
	ring->wb = ring->desc + QDMA_H2C_ST_DESC_SIZE * real_count;
	ring->next_to_use = 0;
	ring->next_to_clean = 0;
	ring->color = 0;


	if (test_bit(q->qid, priv->af_xdp_zc_qps))
	{
		q->xsk_pool = xsk_get_pool_from_qid(priv->netdev, qid);
		if (!q->xsk_pool)
		{
			rv = -ENOMEM;
			netdev_err(dev, "fatal error in setting up the tx queue %d, xsk_pool is NULL", qid);
			goto clear_tx_queue;
		}

		if (xsk_pool_get_rx_frame_size(q->xsk_pool) > PAGE_SIZE)
		{
			rv = -ENOMEM;
			netdev_err(dev, "fatal error in setting up the tx queue %d, xsk_pool frame size is too big", qid);
			goto clear_tx_queue;
		}
	}

	/* initialize TX buffers */
	q->buffer =
		kcalloc(real_count, sizeof(struct onic_tx_buffer), GFP_KERNEL);
	if (!q->buffer) {
		rv = -ENOMEM;
		goto clear_tx_queue;
	}

	/* initialize QDMA H2C queue */
	param.rngcnt_idx = rngcnt_idx;
	param.dma_addr = ring->dma_addr;
	param.vid = vid;
	rv = onic_qdma_init_tx_queue(priv->hw.qdma, qid, &param);
	if (rv < 0)
		goto clear_tx_queue;

	priv->tx_queue[qid] = q;
	return 0;

clear_tx_queue:
	onic_clear_tx_queue(priv, qid);
	return rv;
}

void onic_clear_rx_queue(struct onic_private *priv, u16 qid)
{
	struct onic_rx_queue *q = priv->rx_queue[qid];
	struct onic_ring *ring;
	u32 size, real_count;
	int i;
	
	if (!q)
		return;

	onic_qdma_clear_rx_queue(priv->hw.qdma, qid);

	napi_disable(&q->napi);
	netif_napi_del(&q->napi);
	
	ring = &q->desc_ring;
	real_count = ring->count - 1;
	size = QDMA_C2H_ST_DESC_SIZE * real_count + QDMA_WB_STAT_SIZE;
	size = ALIGN(size, PAGE_SIZE);
	netdev_info(q->netdev, "Cleaning RTX desc_ring #%d ntc %d ntu %d distance=%d",q->qid, ring->next_to_clean, ring->next_to_use, onic_ring_get_occupancy(ring));

	for(i = 0; i < real_count; ++i) {
		
		if (q->page_pool){
			struct page *pg = q->buffer[i].pg;
			if (pg) page_pool_put_full_page(q->page_pool, pg, false);
		} else if (q->xsk_pool) {
			struct xdp_buff *xdp_buff = q->xdps[i];
			if (xdp_buff) xsk_buff_free(xdp_buff);
		} else {
			netdev_err(priv->netdev, "unknown buffer type");
		}
		
	}
	
	if (ring->desc)
		dma_free_coherent(&priv->pdev->dev, size, ring->desc,
				  ring->dma_addr);

	ring = &q->cmpl_ring;
	real_count = ring->count - 1;
	size = QDMA_C2H_CMPL_SIZE * real_count + QDMA_C2H_CMPL_STAT_SIZE;
	size = ALIGN(size, PAGE_SIZE);

	netdev_info(q->netdev, "Cleaning RTX cmpl_ring #%d ntc %d ntu %d distance=%d",q->qid, ring->next_to_clean, ring->next_to_use, onic_ring_get_occupancy(ring));

	if (ring->desc)
		dma_free_coherent(&priv->pdev->dev, size, ring->desc,
				  ring->dma_addr);


	if(q->page_pool){
		if (q->buffer) kfree(q->buffer);
		page_pool_destroy(q->page_pool);
		q->page_pool = NULL;
	}
	
	
	if (xdp_rxq_info_is_reg(&q->xdp_rxq))
		xdp_rxq_info_unreg(&q->xdp_rxq);
	kfree(q);
	priv->rx_queue[qid] = NULL;
	
}


static int onic_create_page_pool(struct onic_private *priv, struct onic_rx_queue *q, int size) {
	struct bpf_prog *xdp_prog = READ_ONCE(priv->xdp_prog);
	struct page_pool_params pp_params = {
		.order = 0,
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.pool_size = size,
		.nid = dev_to_node(&priv->pdev->dev),
		.dev = &priv->pdev->dev,
		.dma_dir = xdp_prog ? DMA_BIDIRECTIONAL : DMA_FROM_DEVICE,
		.offset = XDP_PACKET_HEADROOM,
		.max_len = priv->netdev->mtu + ETH_HLEN,
	};
	int err;

	q->page_pool = page_pool_create(&pp_params);
	if (IS_ERR(q->page_pool)) {
		err = PTR_ERR(q->page_pool);
		q->page_pool = NULL;
		return err;
	}

	err = xdp_rxq_info_reg(&q->xdp_rxq, priv->netdev, q->qid, 0);
	if (err < 0)
		goto err_free_pp;

	err = xdp_rxq_info_reg_mem_model(&q->xdp_rxq, MEM_TYPE_PAGE_POOL,
					 q->page_pool);
	if (err)
		goto err_unregister_rxq;

	return 0;

err_unregister_rxq:
	xdp_rxq_info_unreg(&q->xdp_rxq);
err_free_pp:
	page_pool_destroy(q->page_pool);
	q->page_pool = NULL;
	return err;
}

 
static int onic_init_tx_resource(struct onic_private *priv)
{
	struct net_device *dev = priv->netdev;
	int qid, rv;

	for (qid = 0; qid < priv->num_tx_queues; ++qid) {
		rv = onic_init_tx_queue(priv, qid);
		if (!rv)
			continue;

		netdev_err(dev, "onic_init_tx_queue %d, err = %d", qid, rv);
		goto clear_tx_resource;
	}

	return 0;

clear_tx_resource:
	while (qid--)
		onic_clear_tx_queue(priv, qid);
	return rv;
}

static int onic_init_rx_resource(struct onic_private *priv)
{
	struct net_device *dev = priv->netdev;
	int qid, rv;

	for (qid = 0; qid < priv->num_rx_queues; ++qid) {
		rv = onic_init_rx_queue(priv, qid);
		if (!rv)
			continue;

		netdev_err(dev, "onic_init_rx_queue %d, err = %d", qid, rv);
		goto clear_rx_resource;
	}

	return 0;

clear_rx_resource:
	while (qid--)
		onic_clear_rx_queue(priv, qid);
	return rv;
}

int onic_open_netdev(struct net_device *dev)
{
	struct onic_private *priv = netdev_priv(dev);
	int rv;

	rv = onic_init_tx_resource(priv);
	if (rv < 0)
		goto stop_netdev;

	rv = onic_init_rx_resource(priv);
	if (rv < 0)
		goto stop_netdev;

	netif_tx_start_all_queues(dev);
	netif_carrier_on(dev);
	return 0;

stop_netdev:
	onic_stop_netdev(dev);
	return rv;
}

int onic_stop_netdev(struct net_device *dev)
{
	struct onic_private *priv = netdev_priv(dev);
	int qid;

	/* stop sending */
	netif_carrier_off(dev);
	netif_tx_stop_all_queues(dev);

	for (qid = 0; qid < priv->num_tx_queues; ++qid)
		onic_clear_tx_queue(priv, qid);
	for (qid = 0; qid < priv->num_rx_queues; ++qid)
		onic_clear_rx_queue(priv, qid);

	return 0;
}

netdev_tx_t onic_xmit_frame(struct sk_buff *skb, struct net_device *dev)
{
	struct onic_private *priv = netdev_priv(dev);
	struct onic_tx_queue *q;
	struct onic_ring *ring;
	struct qdma_h2c_st_desc desc;
	// TODO: check how to tell the kernel to ignore a queue if it is configured as a ZC XSK queue
	u16 qid = skb->queue_mapping;
	dma_addr_t dma_addr;
	u8 *desc_ptr;
	int rv;
	bool debug = 0;
	struct rtnl_link_stats64 *pcpu_stats_pointer;
	pcpu_stats_pointer = this_cpu_ptr(priv->netdev_stats);

	q = priv->tx_queue[qid];
	ring = &q->ring;

	onic_tx_clean(q);

	if (onic_ring_full(ring)) {
		if (debug)
			netdev_info(dev, "ring is full");
		return NETDEV_TX_BUSY;
	}

	/* minimum Ethernet packet length is 60 */
	rv = skb_put_padto(skb, ETH_ZLEN);

	if (rv < 0)
		netdev_err(dev, "skb_put_padto failed, err = %d", rv);

	dma_addr = dma_map_single(&priv->pdev->dev, skb->data, skb->len,
				  DMA_TO_DEVICE);

	if (unlikely(dma_mapping_error(&priv->pdev->dev, dma_addr))) {
		dev_kfree_skb(skb);
		pcpu_stats_pointer->tx_dropped++;
		pcpu_stats_pointer->tx_errors++;
		return NETDEV_TX_OK;
	}

	desc_ptr = ring->desc + QDMA_H2C_ST_DESC_SIZE * ring->next_to_use;
	desc.len = skb->len;
	desc.src_addr = dma_addr;
	desc.metadata = skb->len;
	qdma_pack_h2c_st_desc(desc_ptr, &desc);

	q->buffer[ring->next_to_use].type = ONIC_TX_SKB;
	q->buffer[ring->next_to_use].skb = skb;
	q->buffer[ring->next_to_use].dma_addr = dma_addr;
	q->buffer[ring->next_to_use].len = skb->len;

	pcpu_stats_pointer->tx_packets++;
	pcpu_stats_pointer->tx_bytes += skb->len;

	onic_ring_increment_head(ring);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
	if (onic_ring_full(ring) || !netdev_xmit_more()) {
#elif defined(RHEL_RELEASE_CODE)
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 1)
        if (onic_ring_full(ring) || !netdev_xmit_more()) {
#endif
#else
	if (onic_ring_full(ring) || !skb->xmit_more) {
#endif
		wmb();
		onic_set_tx_head(priv->hw.qdma, qid, ring->next_to_use);
	}

	return NETDEV_TX_OK;
}

int onic_set_mac_address(struct net_device *dev, void *addr)
{
	struct sockaddr *saddr = addr;
	u8 *dev_addr = saddr->sa_data;
	if (!is_valid_ether_addr(saddr->sa_data))
		return -EADDRNOTAVAIL;

	netdev_info(dev, "Set MAC address to %02x:%02x:%02x:%02x:%02x:%02x",
			dev_addr[0], dev_addr[1], dev_addr[2],
			dev_addr[3], dev_addr[4], dev_addr[5]);
	eth_hw_addr_set(dev, dev_addr);
	return 0;
}

int onic_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	return 0;
}

int onic_change_mtu(struct net_device *dev, int mtu)
{
	netdev_info(dev, "Requested MTU = %d", mtu);
	return 0;
}

inline void onic_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	struct onic_private *priv = netdev_priv(dev);
	struct rtnl_link_stats64 *pcpu_ptr;
	struct rtnl_link_stats64 total_stats = { };
	unsigned int cpu;
	for_each_possible_cpu(cpu) {
		pcpu_ptr = per_cpu_ptr(priv->netdev_stats, cpu);
		if (!pcpu_ptr) {
			goto out;
		}
		
		total_stats.rx_packets += pcpu_ptr->rx_packets;
		total_stats.rx_bytes += pcpu_ptr->rx_bytes;
		total_stats.tx_packets += pcpu_ptr->tx_packets;
		total_stats.tx_bytes += pcpu_ptr->tx_bytes;
		total_stats.tx_errors += pcpu_ptr->tx_errors;
		total_stats.tx_dropped += pcpu_ptr->tx_dropped;
	}
out:
	stats->tx_packets = total_stats.tx_packets;
	stats->tx_bytes = total_stats.tx_bytes;
	stats->rx_packets = total_stats.rx_packets;
	stats->rx_bytes = total_stats.rx_bytes;
	stats->tx_dropped = total_stats.tx_dropped;
	stats->tx_errors = total_stats.tx_errors;
}


static int onic_setup_xdp_prog(struct net_device *dev, struct bpf_prog *prog) {

	struct onic_private *priv = netdev_priv(dev);
	bool running = netif_running(dev);
	bool need_reset;

	struct bpf_prog *old_prog = xchg(&priv->xdp_prog, prog);
	need_reset = (!!prog != !!old_prog);

	if (need_reset && running) {
		onic_stop_netdev(dev);
	} else {
		
		int i;
		for (i = 0; i < priv->num_rx_queues; i++) {
			xchg(&priv->rx_queue[i]->xdp_prog, priv->xdp_prog);
		}
	}
	if (old_prog){
		bpf_prog_put(old_prog);
	}

	/* bpf is just replaced, RXQ and MTU are already setup */
	if (!need_reset)
		return 0;

	if (running)
		onic_open_netdev(dev);

	return 0;
}

int onic_xdp(struct net_device *dev, struct netdev_bpf *xdp) {
	if (!xdp){
		netdev_err(dev, "xdp is NULL");
		return -EINVAL;
	}
	switch (xdp->command) {
		case XDP_SETUP_PROG:
			netdev_info(dev, "xdp setup prog");
			return onic_setup_xdp_prog(dev, xdp->prog);
		case XDP_SETUP_XSK_POOL:
			netdev_info(dev, "xdp setup pool");
			return onic_xsk_pool_setup(dev, xdp->xsk.pool, xdp->xsk.queue_id);
		default:
			return -EINVAL;
	}
}

int onic_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames, u32 flags) {
	struct onic_private *priv = netdev_priv(dev);
	struct onic_ring *tx_ring;
	struct onic_tx_queue *tx_queue;
	struct netdev_queue *nq;
	int i, drops = 0, cpu = smp_processor_id();

	tx_queue =  onic_xdp_tx_queue_mapping(priv);

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK)){
			netdev_err(dev, "Invalid flags");
		tx_queue->xdp_tx_stats.xdp_xmit_err++;
		return -EINVAL;
	}

	tx_ring = &tx_queue->ring;
	nq = netdev_get_tx_queue(tx_queue->netdev, tx_queue->qid);

	__netif_tx_lock(nq, cpu);
	for (i = 0; i < n; i++) {
		struct xdp_frame *frame = frames[i];
		int err;

		err = 0;
		err = onic_xmit_xdp_ring(priv, tx_queue, frame, true);
		if (err != ONIC_XDP_TX) {
			xdp_return_frame_rx_napi(frame);
			netdev_err(dev, "Failed to transmit frame");
			tx_queue->xdp_tx_stats.xdp_xmit_err++;
			drops++;
		} else {
			tx_queue->xdp_tx_stats.xdp_xmit++;
		}
	}

	if (flags & XDP_XMIT_FLUSH) {
		wmb();
		onic_set_tx_head(priv->hw.qdma, tx_queue->qid, tx_queue->ring.next_to_use);
	}
	__netif_tx_unlock(nq);



	return n - drops;
}

static int onic_rx_zc_poll(struct napi_struct *napi, int budget)
{
	struct onic_rx_queue *q = container_of(napi, struct onic_rx_queue, napi);
	struct onic_private *priv = netdev_priv(q->netdev);
	u16 qid = q->qid;
	struct onic_ring *desc_ring = &q->desc_ring;
	struct onic_ring *cmpl_ring = &q->cmpl_ring;
	struct qdma_c2h_cmpl cmpl;
	struct qdma_c2h_cmpl_stat cmpl_stat;
	u8 *cmpl_ptr;
	u8 *cmpl_stat_ptr;
	u32 color_stat;
	int work = 0;
	int i, rv, err;
	bool flipped = 0;
	bool alloc_err_xsk = false;
	bool tx_wake;

	unsigned int xdp_xmit = 0;
	struct rtnl_link_stats64 *pcpu_stats_pointer;
	pcpu_stats_pointer = this_cpu_ptr(priv->netdev_stats);

	for (i = 0; i < priv->num_tx_queues; i++)
	{
		onic_tx_clean(priv->tx_queue[i]);
		if (qid == i && test_bit(qid, priv->af_xdp_zc_qps) && q->xsk_pool)
		{
			// onic_update_tx_need_wakeup(priv->tx_queue[qid]);
			tx_wake = onic_xsk_xmit(priv, priv->tx_queue[qid]);
			onic_update_tx_need_wakeup(priv->tx_queue[qid], tx_wake);
		}
	}

	cmpl_ptr = cmpl_ring->desc + QDMA_C2H_CMPL_SIZE * cmpl_ring->next_to_clean;
	cmpl_stat_ptr = cmpl_ring->desc + QDMA_C2H_CMPL_SIZE * (cmpl_ring->count - 1);

	qdma_unpack_c2h_cmpl(&cmpl, cmpl_ptr);
	qdma_unpack_c2h_cmpl_stat(&cmpl_stat, cmpl_stat_ptr);

	color_stat = cmpl_stat.color;

	while ((cmpl_ring->next_to_clean != cmpl_stat.pidx))
	{

		struct sk_buff *skb;
		int xdp_result;

		int len = cmpl.pkt_len;

		struct xdp_buff *xdp_buff = q->xdps[desc_ring->next_to_clean];

		xdp_buff->data_end = xdp_buff->data + len;
		xsk_buff_dma_sync_for_cpu(xdp_buff, q->xsk_pool);
		xdp_result = onic_run_xdp_zc(q, xdp_buff);
		xdp_xmit |= xdp_result;
		if (xdp_result == ONIC_XDP_CONSUMED)
		{
			xsk_buff_free(xdp_buff);
		}
		else if (xdp_result == ONIC_XDP_PASS)
		{
			skb = onic_xsk_construct_skb(napi, xdp_buff);
			if (skb)
			{
				skb_record_rx_queue(skb, q->qid);
				skb->protocol = eth_type_trans(skb, q->netdev);
				err = napi_gro_receive(napi, skb);
				if (err < 0)
				{
					netdev_err(q->netdev, "napi_gro_receive, err = %d", rv);
				}
			}
			xsk_buff_free(xdp_buff);
		}

		pcpu_stats_pointer->rx_packets++;
		pcpu_stats_pointer->rx_bytes += len;

		//NULL the pointer
		q->xdps[desc_ring->next_to_clean] = NULL;

		onic_ring_increment_tail(desc_ring);

		onic_ring_increment_tail(cmpl_ring);

		if (cmpl.color != cmpl_ring->color)
		{
			cmpl_ring->color = (cmpl_ring->color == 0) ? 1 : 0;
			flipped = 1;
		}
		cmpl_ptr =
			cmpl_ring->desc + (QDMA_C2H_CMPL_SIZE * cmpl_ring->next_to_clean);

		if ((++work) >= budget)
		{
			goto out_of_budget;
			// if (xdp_xmit & ONIC_XDP_REDIR)
			// 	xdp_do_flush();

			// // napi will be rescheduled. Keep irq disabled.
			// return work;
		}

		// read next completion descriptor
		qdma_unpack_c2h_cmpl(&cmpl, cmpl_ptr);
	}

out_of_budget:	
	if (onic_rx_zc_refill(q,work) != work)
	{
		alloc_err_xsk = true;
	}


	if (xdp_xmit & ONIC_XDP_REDIR)
		xdp_do_flush();

	if (!xsk_uses_need_wakeup(q->xsk_pool) && alloc_err_xsk)
	{
		return budget;
	}

	return work;
}

static int onic_clean_rx_poll(struct napi_struct *napi, int budget)
{
	struct onic_rx_queue *q = container_of(napi, struct onic_rx_queue, napi);
	struct onic_private *priv = netdev_priv(q->netdev);
	u16 qid = q->qid;
	struct onic_ring *desc_ring = &q->desc_ring;
	struct onic_ring *cmpl_ring = &q->cmpl_ring;
	struct qdma_c2h_cmpl cmpl;
	struct qdma_c2h_cmpl_stat cmpl_stat;
	u8 *cmpl_ptr;
	u8 *cmpl_stat_ptr;
	u32 color_stat;
	int work = 0;
	int i, rv;
	bool debug = 1;
	void *res;

	struct xdp_buff xdp;
	unsigned int xdp_xmit = 0;
	struct rtnl_link_stats64 *pcpu_stats_pointer;
	pcpu_stats_pointer = this_cpu_ptr(priv->netdev_stats);

	if (debug)
		netdev_info(q->netdev, "%s qid %d", __func__, qid);

	for (i = 0; i < priv->num_tx_queues; i++)
	{
		onic_tx_clean(priv->tx_queue[i]);
	}

	cmpl_ptr = cmpl_ring->desc + QDMA_C2H_CMPL_SIZE * cmpl_ring->next_to_clean;
	cmpl_stat_ptr = cmpl_ring->desc + QDMA_C2H_CMPL_SIZE * (cmpl_ring->count - 1);

	qdma_unpack_c2h_cmpl(&cmpl, cmpl_ptr);
	qdma_unpack_c2h_cmpl_stat(&cmpl_stat, cmpl_stat_ptr);

	color_stat = cmpl_stat.color;

	if (cmpl.err == 1)
	{
		if (debug)
			netdev_info(q->netdev, "completion error detected in cmpl entry!");
		// todo: need to handle the error ...
		onic_qdma_clear_error_interrupt(priv->hw.qdma);
	}

	while ((cmpl_ring->next_to_clean != cmpl_stat.pidx))
	{
		struct sk_buff *skb;
		int len = cmpl.pkt_len;
		struct onic_rx_buffer *buf = &q->buffer[desc_ring->next_to_clean];
		
		xdp_init_buff(&xdp, PAGE_SIZE, &q->xdp_rxq);

		dma_sync_single_for_cpu(&priv->pdev->dev,
								page_pool_get_dma_addr(buf->pg) + buf->offset,
								len, DMA_FROM_DEVICE);

		xdp_prepare_buff(&xdp, page_address(buf->pg), buf->offset, len, false);
		res = onic_run_xdp(q, &xdp);
		if (IS_ERR(res))
		{
			unsigned int xdp_res = -PTR_ERR(res);

			if (xdp_res & (ONIC_XDP_TX | ONIC_XDP_REDIR))
			{
				xdp_xmit |= xdp_res;
			}

			// Allocate skb only if we are continuing to process the packet
			if (xdp_res & ONIC_XDP_PASS)
			{

				// allocate a new skb structure around the data
				skb = napi_build_skb(xdp.data_hard_start, PAGE_SIZE);

				if (!skb)
				{
					rv = -ENOMEM;
					break;
				}

				// mark the skb for page_pool recycling
				skb_mark_for_recycle(skb);
				// reserve space in the skb for the data for the xdp headroom
				skb_reserve(skb, xdp.data - xdp.data_hard_start);
				// set the data pointer
				skb_put(skb, xdp.data_end - xdp.data);

				skb->protocol = eth_type_trans(skb, q->netdev);
				skb->ip_summed = CHECKSUM_NONE;
				skb_record_rx_queue(skb, qid);
				rv = napi_gro_receive(napi, skb);
				if (rv < 0)
				{
					netdev_err(q->netdev, "napi_gro_receive, err = %d", rv);
					break;
				}
			}
		}
	
		pcpu_stats_pointer->rx_packets++;
		pcpu_stats_pointer->rx_bytes += len;
		//NULL the pointer
		buf->pg = NULL;
		buf->offset = 0;
			
		onic_ring_increment_tail(desc_ring);


		onic_ring_increment_tail(cmpl_ring);
		cmpl_ptr = cmpl_ring->desc + (QDMA_C2H_CMPL_SIZE * cmpl_ring->next_to_clean);

		  if ((++work) >= budget) {
			goto out_of_budget;
		  }

		  qdma_unpack_c2h_cmpl(&cmpl, cmpl_ptr);
	}

	
out_of_budget:	
	onic_rx_pp_refill(q, work);
	
	if (xdp_xmit & ONIC_XDP_REDIR)
    xdp_do_flush();

	return work;
}

static int onic_rx_poll(struct napi_struct *napi, int budget)
{
	struct onic_rx_queue *q = container_of(napi, struct onic_rx_queue, napi);
	struct onic_private *priv = netdev_priv(q->netdev);
	bool irq_rearm = 0;
	u16 qid = q->qid;
	int work_done;

	//TODO:  extract here the polling of tx completion.

	if (q->xsk_pool && test_bit(qid, priv->af_xdp_zc_qps))
	{
		work_done = onic_rx_zc_poll(napi, budget);
	}
	else
	{
		work_done = onic_clean_rx_poll(napi, budget);
	}
	if (work_done < budget)
	{
		irq_rearm = napi_complete_done(napi, work_done);
	}

	onic_set_completion_tail(priv->hw.qdma, qid, q->cmpl_ring.next_to_clean,
							 irq_rearm);
	onic_set_rx_head(priv->hw.qdma, qid, q->desc_ring.next_to_use);


	return work_done;
}



int onic_init_rx_queue(struct onic_private *priv, u16 qid)
{
	// TODO: make these configurable via ethtool
	const u8 bufsz_idx = 8;
	const u8 desc_rngcnt_idx = 8;
	//const u8 cmpl_rngcnt_idx = 15;
	const u8 cmpl_rngcnt_idx = 8;
	struct net_device *dev = priv->netdev;
	struct onic_rx_queue *q;
	struct onic_ring *ring;
	struct onic_qdma_c2h_param param;
	u16 vid;
	u32 size, real_count;
	int i, rv;
	bool debug = 1;
	int err;
	int buffers_allocated = 0;
	
	if (priv->rx_queue[qid]) {
		if (debug)
			netdev_info(dev, "Re-initializing RX queue %d", qid);
		onic_clear_rx_queue(priv, qid);
	}

	q = kzalloc(sizeof(struct onic_rx_queue), GFP_KERNEL);
	if (!q)
		return -ENOMEM;

	/* evenly assign to RX queues available vectors */
	vid = qid % priv->num_q_vectors;

	q->netdev = dev;
	q->vector = priv->q_vector[vid];
	q->qid = qid;

	q->xdp_prog = priv->xdp_prog;

	/* allocate DMA memory for RX descriptor ring */
	ring = &q->desc_ring;
	ring->count = onic_ring_count(desc_rngcnt_idx);
	real_count = ring->count - 1;

	size = QDMA_C2H_ST_DESC_SIZE * real_count + QDMA_WB_STAT_SIZE;
	size = ALIGN(size, PAGE_SIZE);
	ring->desc = dma_alloc_coherent(&priv->pdev->dev, size, &ring->dma_addr,
					GFP_KERNEL);
	if (!ring->desc) {
		rv = -ENOMEM;
		goto clear_rx_queue;
	}
	memset(ring->desc, 0, size);
	ring->wb = ring->desc + QDMA_C2H_ST_DESC_SIZE * real_count;
	ring->next_to_use = 0;
	ring->next_to_clean = 0;
	ring->color = 0;

	if (test_bit(qid, priv->af_xdp_zc_qps)) {
		q->xsk_pool = xsk_get_pool_from_qid(dev, qid);
		if (!q->xsk_pool) {
			rv = -ENOMEM;
			netdev_err(dev, "fatal error: xsk_pool is NULL at queue %d but the state bit is set", qid);
			goto clear_rx_queue;
		}


		err = xdp_rxq_info_reg(&q->xdp_rxq, priv->netdev, q->qid, 0);
		if (err)
			goto clear_rx_queue;

		err = xdp_rxq_info_reg_mem_model(&q->xdp_rxq, MEM_TYPE_XSK_BUFF_POOL,
						NULL);
		if (err)
			goto clear_rx_queue;
		
		xsk_pool_set_rxq_info(q->xsk_pool, &q->xdp_rxq);

		// af_xdp zero copy allocator stuff
		q->xdps = kcalloc(real_count, sizeof(struct xdp_buff *), GFP_KERNEL);
		if (!q->xdps) {
			rv = -ENOMEM;
			goto clear_rx_queue;
		}

		for (i = 0; i < real_count; ++i) {
			q->xdps[i] = xsk_buff_alloc(q->xsk_pool);
			if (!q->xdps[i]) {
				netdev_err(dev, "xsk_buff_alloc failed at %d", i);
				break;
			}
			buffers_allocated++;
		}

		for (i=0; i < buffers_allocated; ++i) {

			u8 *desc_ptr = ring->desc + QDMA_C2H_ST_DESC_SIZE * i;
			struct qdma_c2h_st_desc desc;
			desc.dst_addr = xsk_buff_xdp_get_dma(q->xdps[i]);
			qdma_pack_c2h_st_desc(desc_ptr, &desc);

		}
	} else {
		// normal page pool stuff
		/* initialize RX buffers */
		q->buffer =
			kcalloc(real_count, sizeof(struct onic_rx_buffer), GFP_KERNEL);
		if (!q->buffer) {
			rv = -ENOMEM;
			goto clear_rx_queue;
		}

		rv = onic_create_page_pool(priv, q, real_count);
		if (rv < 0)
			goto clear_rx_queue;
		

		for (i = 0; i < real_count; ++i) {
			struct page *pg = page_pool_dev_alloc_pages(q->page_pool);

			if (!pg) {
				netdev_err(dev, "page_pool_dev_alloc_pages failed at %d", i);
				break;
			}

			q->buffer[i].pg = pg;
			q->buffer[i].offset = XDP_PACKET_HEADROOM;
			buffers_allocated++;
		}

		

		/* map pages and initialize descriptors */
		for (i = 0; i < buffers_allocated ; ++i) {
			u8 *desc_ptr = ring->desc + QDMA_C2H_ST_DESC_SIZE * i;
			struct qdma_c2h_st_desc desc;
			struct page *pg = q->buffer[i].pg;
			unsigned int offset = q->buffer[i].offset;

			desc.dst_addr = page_pool_get_dma_addr(pg) + offset;
			qdma_pack_c2h_st_desc(desc_ptr, &desc);
		}

	}


	/* allocate DMA memory for completion ring */
	ring = &q->cmpl_ring;
	ring->count = onic_ring_count(cmpl_rngcnt_idx);
	real_count = ring->count - 1;

	size = QDMA_C2H_CMPL_SIZE * real_count + QDMA_C2H_CMPL_STAT_SIZE;
	size = ALIGN(size, PAGE_SIZE);
	ring->desc = dma_alloc_coherent(&priv->pdev->dev, size, &ring->dma_addr,
					GFP_KERNEL);
	if (!ring->desc) {
		rv = -ENOMEM;
		goto clear_rx_queue;
	}
	memset(ring->desc, 0, size);
	ring->wb = ring->desc + QDMA_C2H_CMPL_SIZE * real_count;
	ring->next_to_use = 0;
	ring->next_to_clean = 0;
	ring->color = 1;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
	netif_napi_add(dev, &q->napi, onic_rx_poll);
#else
	netif_napi_add(dev, &q->napi, onic_rx_poll, 64);
#endif

	/* initialize QDMA C2H queue */
	param.bufsz_idx = bufsz_idx;
	param.desc_rngcnt_idx = desc_rngcnt_idx;
	param.cmpl_rngcnt_idx = cmpl_rngcnt_idx;
	param.cmpl_desc_sz = 0;
	param.desc_dma_addr = q->desc_ring.dma_addr;
	param.cmpl_dma_addr = q->cmpl_ring.dma_addr;
	param.vid = vid;
	if (debug)
		netdev_info(
			dev,
			"bufsz_idx %u, desc_rngcnt_idx %u, cmpl_rngcnt_idx %u, desc_dma_addr 0x%llx, cmpl_dma_addr 0x%llx, vid %d",
			bufsz_idx, desc_rngcnt_idx, cmpl_rngcnt_idx,
			q->desc_ring.dma_addr, q->cmpl_ring.dma_addr, vid);

	rv = onic_qdma_init_rx_queue(priv->hw.qdma, qid, &param);
	if (rv < 0)
		goto clear_rx_queue;

	/* fill RX descriptor ring with a few descriptors */
	q->desc_ring.next_to_use =  buffers_allocated % (real_count);
	onic_set_rx_head(priv->hw.qdma, qid, q->desc_ring.next_to_use);
	onic_set_completion_tail(priv->hw.qdma, qid, 0, 1);

	priv->rx_queue[qid] = q;
	napi_enable(&q->napi);
	return 0;

clear_rx_queue:
	netdev_err(dev, "onic_init_rx_queue %d failed, err = %d", qid, rv);
	onic_clear_rx_queue(priv, qid);
	return rv;
}
