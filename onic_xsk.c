#include <linux/bpf_trace.h>
#include <linux/stringify.h>
#include <net/xdp_sock_drv.h>
#include <net/xdp.h>

#include "onic.h"
#include "onic_xsk.h"
#include "onic_lib.h"
#include "onic_netdev.h"

int onic_alloc_rx_xpds(struct onic_rx_queue *rx_queue)
{
	unsigned long size = sizeof(*rx_queue->xdps) * onic_ring_get_real_count(&rx_queue->ring);
	rx_queue->xdps = kzalloc(size, GFP_KERNEL);
	return rx_queue->xdps ? 0 : -ENOMEM;
}

bool onic_alloc_rx_buffers_zc(struct onic_rx_queue *rx_queue, u16 count)
{

	struct onic_private *priv = netdev_priv(rx_queue->netdev);
	struct onic_ring *ring = &rx_queue->ring;
	struct xpd_buff *xdp, **xdps;
	struct dma_addr_t dma;
	xdps = &rx_queue->xdps[ring->next_to_use];
	u8 *desc_ptr;
	struct qdma_c2h_st_desc desc;

	bool ret = true;

	do
	{

		xdp = xsk_buff_alloc(rx_queue->xsk_pool);
		if (!xdp)
		{
			ret = false;
			goto no_buffers;
		}

		*xdps = xdp;
		dma = xsk_buff_get_dma(xdp);
		desc_ptr = ring->desc + QDMA_C2H_ST_DESC_SIZE * ring->next_to_use;
		desc.dst_addr = dma;
		qdma_pack_c2h_st_desc(desc_ptr, &desc);
		onic_ring_increment_head(ring);
		xdps++;

	} while (--count);

no_buffers:

	onic_set_rx_head(priv->hw.qdma, rx_queue->qid, ring->next_to_use);
	return ret;
}

int onic_run_xdp_zc(struct xdp_buff *xdp, struct onic_rx_queue *rx_queue)
{

	u32 act;
	int err, result = ONIC_XDP_PASS;

	struct bpf_prog *xdp_prog = rx_queue->xdp_prog;

	if (unlikely(!xdp_prog))
	{
		// this would be a catastrophic error as the zero copy path is allowed only when a xdp program is loaded
		// TODO : log this error
		netdev_err(rx_queue->netdev, "XDP program not loaded for AF_XDP_ZC\n");
	}

	act = bpf_prog_run_xdp(xdp_prog, xdp);

	if (likely(act == XDP_REDIRECT))
	{
		err = xdp_do_redirect(rx_queue->netdev, xdp, xdp_prog);
		if (err)
			goto failure;
		return ONIC_XDP_REDIR;
	}

	switch (act)
	{
	case XDP_PASS:
		rx_queue->xdp_rx_stats.xdp_pass++;
		break;
	case XDP_TX:
		rx_queue->xdp_rx_stats.xdp_tx++;
		result = onic_xdp_xmit_back(rx_queue, xdp_buff);
		if (result == ONIC_XDP_CONSUMED)
			goto failure;
		break;
	default:
		bpf_warn_invalid_xdp_action(act);
		fallthrough;
	case XDP_ABORTED:
	failure:
		trace_xdp_exception(rx_queue->netdev, xdp_prog, act);
		fallthrough;
	case XDP_DROP:
		rx_queue->xdp_rx_stats.xdp_drop++;
		result = ONIC_XDP_CONSUMED;
		break;
	}

	return result;
}

struct sk_buff *onic_xsk_construct_skb(struct napi_struct *napi, struct xdp_buff *xdp)
{

	struct sk_buff *skb;
	u32 data_size = xdp->data_end - xdp->data;
	u32 length = xdp->data_end - xdp->data_hard_start;

	skb = napi_alloc_skb(napi, length);
	if (unlikely(!skb))
	{
		// report error via some counters i'll decide later
		return NULL;
	}

	skb_reserve(skb, xdp->data - xdp->data_hard_start);

	skb_put_data(skb, xdp->data, data_size);
	skb->protocol = eth_type_trans(skb, q->netdev);
	skb->ip_summed = CHECKSUM_NONE;
	return skb;
}

int onic_rx_consume_zc(struct onic_rx_queue *rx_queue, struct qdma_c2h_cmpl_stat cmpl_stat)
{

	struct onic_private *priv = netdev_priv(rx_queue->netdev);
	struct onic_ring *desc_ring = &rx_queue->desc_ring;
	struct onic_ring *cmpl_ring = &rx_queue->cmpl_ring;
	struct qdma_c2h_cmpl cmpl;
	struct napi_struct *napi = &rx_queue->napi;
	u8 *cmpl_ptr;

	struct xdp_buff *xdp_buff;
	int xdp_result;
	int len, err;

	while ((cmpl_ring->next_to_clean != cmpl_stat.pidx))
	{
		struct sk_buff *skb;
		xdp_buff = rx_queue->xdps[desc_ring->next_to_clean];

		cmpl_ptr =
			cmpl_ring->desc + QDMA_C2H_CMPL_SIZE * cmpl_ring->next_to_clean;

		qdma_unpack_c2h_cmpl(&cmpl, cmpl_ptr);
		len = cmpl.pkt_len;
		xdp_buff->data_end = xdp_buff->data + len;

		xsk_buff_dma_sync_for_cpu(xdp_buff, xsk_get_pool_from_qid(priv->netdev, rx_queue->qid));

		xdp_result = onic_run_xdp_zc(xdp_buff, rx_queue);

		if (xdp_result == ONIC_XDP_CONSUMED)
		{
			xsk_buff_free(xdp_buff);
		}
		else if (xdp_result == ONIC_XDP_PASS)
		{
			skb = onic_xsk_construct_skb(napi, xdp_buff);
			if (skb)
			{
				skb_record_rx_queue(skb, rx_queue->qid);
				err = napi_gro_receive(napi, skb);
				if (err < 0)
				{
					netdev_err(q->netdev, "napi_gro_receive, err = %d", rv);
				}
				
			}

		}
	}
}

static int onic_xsk_wakeup(struct net_device *dev, u16 qid, u32 flags)
{
	return -1;
}

/**
 * onic_xsk_pool_setup - Enable or disable XSK pool
 * @priv: pointer to onic_private
 * @pool: buffer pool to enable/associate, NULL to disable
 * @qid: Rx ring to operate on
 *
 * return 0 on success, negative on failure
 */

static int onic_xsk_pool_enable(struct onic_private *priv, struct xsk_buff_pool *pool, u16 qid)
{

	int err;
	bool if_running;

	if (qid >= priv->num_rx_queues || qid >= priv->num_tx_queues)
		return -EINVAL;

	err = xsk_pool_dma_map(pool, &priv->pdev->dev, DMA_ATTR_SKIP_CPU_SYNC);
	if (err)
		return err;

	set_bit(qid, priv->af_xdp_zc_qps);

	if_running = netif_running(priv->netdev);

	if (if_running)
	{
		// TODO
		err = onic_queue_pair_disable(priv, qid);
		if (err)
			return err;

		err = onic_queue_pair_enable(priv, qid);
		if (err)
			return err;

		/* Kick start the NAPI context so that receiving will start */
		err = onic_xsk_wakeup(priv->netdev, qid, XDP_WAKEUP_RX);
		if (err)
			return err;
	}
}

int onic_xsk_pool_setup(struct onic_private *priv, struct xsk_buff_pool *pool, u16 qid)
{

	return pool = onic_xsk_pool_enable(priv, pool, qid) : onic_xsk_pool_disable(priv, qid);
}



int onic_queue_pair_disable(struct onic_private *priv, u16 qid) {

	struct onic_rx_queue *rx_queue = priv->rx_queue[qid];
	int real_count = onic_ring_get_real_count(&priv->rx_queue[qid]->ring);
	struct netdev_queue *txq = netdev_get_tx_queue(priv->dev, qid);
	// disable interrupts for the queue
	onic_disable_q_vector(priv->q_vector[qid]);
	// disable napi (if there is a napi instance running this will block until it is done)
	napi_disable(&priv->rx_queue[qid]->napi);

	// after disabling the napi i have a doubt: do i have to consume the packets that may be still in the queue ,something like 
	// gro_receive (here we're not in napi context) ? Or i just de alloc all the pages and i ignore the question.
	// for now i'll go with the second option.

	netif_tx_stop_queue(txq);

	onic_tx_clean(priv, qid);
	onic_clear_rx_queue(priv, qid);
	onic_clear_tx_queue(priv, qid);
	
}

int onic_queue_pair_enable(struct onic_private *priv, u16 qid) {
	
	struct onic_rx_queue *rx_queue = priv->rx_queue[qid];
	int real_count = onic_ring_get_real_count(&priv->rx_queue[qid]->ring);
	struct netdev_queue *txq = netdev_get_tx_queue(priv->dev, qid);

	onic_init_rx_queue(priv, qid);
	onic_init_tx_queue(priv, qid);

	netif_tx_wake_queue(txq);
	napi_enable(&priv->rx_queue[qid]->napi);
	onic_enable_q_vector(priv->q_vector[qid]);

}