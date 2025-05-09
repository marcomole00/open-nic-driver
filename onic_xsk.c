#include <linux/netdevice.h>
#include <linux/bpf_trace.h>
#include <linux/pci.h>
#include <linux/stringify.h>
#include <net/xdp_sock_drv.h>
#include <net/xdp.h>

#include "onic.h"
#include "onic_xsk.h"
#include "onic_lib.h"
#include "onic_netdev.h"
#include "xclbin.h"

bool onic_xsk_xmit(struct onic_private *priv, struct onic_tx_queue *q)
{

	u8 *desc_ptr;
	dma_addr_t dma_addr;
	struct onic_ring *ring = &q->ring;
	struct qdma_h2c_st_desc desc;
	struct xdp_desc xdp_desc;
	int trasmitted = 0;
	bool wake_up = false;
	int unused = (ring->next_to_clean > ring->next_to_use? 0 :
		onic_ring_get_real_count(ring)) + ring->next_to_clean- ring->next_to_use - 1;
	while (trasmitted < unused)
	{
		// xsk_tx_peek_desc it's the function that fetches the xdp frames from the
		// TX ring of the xsk buff pool
		if (!xsk_tx_peek_desc(q->xsk_pool, &xdp_desc))
		{
			wake_up = true; // tx ring is empty 
			break;
		}
		trasmitted++;
		dma_addr = xsk_buff_raw_get_dma(q->xsk_pool, xdp_desc.addr);
		xsk_buff_raw_dma_sync_for_device(q->xsk_pool, dma_addr,
										 xdp_desc.len);

		desc_ptr = ring->desc + QDMA_H2C_ST_DESC_SIZE * ring->next_to_use;
		desc.len = xdp_desc.len;
		desc.src_addr = dma_addr;
		desc.metadata = xdp_desc.len;
		qdma_pack_h2c_st_desc(desc_ptr, &desc);

		// the problem here is: the reclaiming of the pages is handled by the xsk api
		q->buffer[ring->next_to_use].type = ONIC_TX_XSK;
		q->buffer[ring->next_to_use].xdpf = NULL;
		q->buffer[ring->next_to_use].dma_addr = dma_addr;
		q->buffer[ring->next_to_use].len = xdp_desc.len;

		onic_ring_increment_head(ring);
	}
	if (trasmitted)
		xsk_tx_release(q->xsk_pool);

	onic_set_tx_head(priv->hw.qdma, q->qid, ring->next_to_use);
	return wake_up;
}


int onic_run_xdp_zc(struct onic_rx_queue *rx_queue, struct xdp_buff *xdp_buff)
{

	u32 act;
	int err, result = ONIC_XDP_PASS;

	struct bpf_prog *xdp_prog = rx_queue->xdp_prog;

	if (unlikely(!xdp_prog))
	{
		// this would be a catastrophic error as the zero copy path is allowed only when a xdp program is loaded
		// TODO : log this error
		netdev_err(rx_queue->netdev, "XDP program not loaded for AF_XDP_ZC\n");
		return ONIC_XDP_CONSUMED;
	}

	act = bpf_prog_run_xdp(xdp_prog, xdp_buff);

	if (likely(act == XDP_REDIRECT))
	{
		err = xdp_do_redirect(rx_queue->netdev, xdp_buff, xdp_prog);
		rx_queue->xdp_rx_stats.xdp_redirect++;
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
	skb->ip_summed = CHECKSUM_NONE;
	return skb;
}

int onic_xsk_wakeup(struct net_device *dev, u32 qid, u32 flags) {
  struct onic_private *priv = netdev_priv(dev);
  struct onic_rx_queue *rx_queue = priv->rx_queue[qid];

  // test that the queue exists and that it is an AF_XDP_ZC queue
  if (qid >= priv->num_rx_queues || qid >= priv->num_tx_queues)
    return -EINVAL;

	if(!rx_queue){
		netdev_err(dev, "rx_queue is null");
		return -EINVAL;
	}

  if (!test_bit(qid, priv->af_xdp_zc_qps) || !rx_queue->xsk_pool) {
    netdev_err(dev, "bit is not set or the pool pointer is null");
    return -EINVAL;
  }

  if (!napi_if_scheduled_mark_missed(&rx_queue->napi)) {
    // this is not ideal: the best thing would be to trigger an irq. The irq
    // would maintain core affinity. instead i'm using a napi_schedule which
    // will run on the current core. This shouldn't be a huge problems because
    // napi context is a softirq and it guarantees that the same napi instance
    // will not run on two different cores at the same time.
    napi_schedule(&rx_queue->napi);
    // onic_set_completion_tail(priv->hw.qdma, qid, rx_queue->cmpl_ring->next_to_clean,1)
    // it's better because it generate an interrupt, triggered by the cidx update
		// if the ring is empty it still does not generate an interrupt
  }

  return 0;
}

/**
 * onic_xsk_pool_setup - Enable or disable XSK pool
 * @priv: pointer to onic_private
 * @pool: buffer pool to enable/associate, NULL to disable
 * @qid: Rx ring to operate on
 *
 * return 0 on success, negative on failure
 */

int onic_xsk_pool_enable(struct onic_private *priv, struct xsk_buff_pool *pool,
                         u16 qid) {

  int err;
  bool if_running;

  if (qid >= priv->num_rx_queues || qid >= priv->num_tx_queues)
    return -EINVAL;
	
  err = xsk_pool_dma_map(pool, &priv->pdev->dev, DMA_ATTR_SKIP_CPU_SYNC);
  if (err){
	netdev_err(priv->netdev, "Error in xsk pool dma map");
    return err;
	}

  set_bit(qid, priv->af_xdp_zc_qps);

  if_running = netif_running(priv->netdev);

  if (if_running) {
    onic_queue_pair_disable(priv, qid);
    onic_queue_pair_enable(priv, qid);
    /* Kick start the NAPI context so that receiving will start */
    err = onic_xsk_wakeup(priv->netdev, qid, XDP_WAKEUP_RX);
    if (err) {
      netdev_err(priv->netdev, "err in xsk wakeup");
      return err;
    }
  }
  return 0;
}

int onic_xsk_pool_disable(struct onic_private *priv, u16 qid)
{
	struct xsk_buff_pool *pool = priv->rx_queue[qid]->xsk_pool;
	if (qid >= priv->num_rx_queues || qid >= priv->num_tx_queues)
		return -EINVAL;



	onic_queue_pair_disable(priv, qid);
	clear_bit(qid, priv->af_xdp_zc_qps);
	xsk_pool_dma_unmap(pool, DMA_ATTR_SKIP_CPU_SYNC |  DMA_ATTR_WEAK_ORDERING );
	onic_queue_pair_enable(priv, qid);

	
	return 0;
}
int onic_xsk_pool_setup(struct net_device *netdev, struct xsk_buff_pool *pool, u16 qid)
{	
	struct onic_private *priv = netdev_priv(netdev);

	if (pool) {
		return onic_xsk_pool_enable(priv, pool, qid);
	} else {
		netdev_info(netdev, "Disabling xsk pool for queue %d", qid);
		return onic_xsk_pool_disable(priv, qid);
	}
}

void onic_queue_pair_disable(struct onic_private *priv, u16 qid)
{

	struct netdev_queue *txq = netdev_get_tx_queue(priv->netdev, qid);
	// disable interrupts for the queue
	netdev_info(priv->netdev, "Disabling queue pair %d", qid);
	onic_disable_q_vector(priv->q_vector[qid]);
	
	// gro_receive (here we're not in napi context) ? Or i just de alloc all the pages and i ignore the question.
	// for now i'll go with the second option.

	netdev_info(priv->netdev, "Disabling tx queue %d", qid);
	netif_tx_stop_queue(txq);
	netdev_info(priv->netdev, "cleaning tx queue %d", qid);
	onic_tx_clean(priv->tx_queue[qid]);
	netdev_info(priv->netdev, "clearing rx queue %d", qid);
	onic_clear_rx_queue(priv, qid);
	netdev_info(priv->netdev, "clearing tx queue %d", qid);
	onic_clear_tx_queue(priv, qid);
}

void onic_queue_pair_enable(struct onic_private *priv, u16 qid)
{

	// struct onic_rx_queue *rx_queue = priv->rx_queue[qid];
	// int real_count = onic_ring_get_real_count(&priv->rx_queue[qid]->ring);
	struct netdev_queue *txq = netdev_get_tx_queue(priv->netdev, qid);
	netdev_info(priv->netdev, "Enabling queue pair %d", qid);
	// this already enables napi
	onic_init_rx_queue(priv, qid);
	onic_init_tx_queue(priv, qid);

	netif_tx_wake_queue(txq);
	onic_enable_q_vector(priv->q_vector[qid]);
}
