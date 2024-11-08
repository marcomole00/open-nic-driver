#include <linux/bpf_trace.h>
#include <linux/stringify.h>
#include <net/xdp_sock_drv.h>
#include <net/xdp.h>

#include "onic.h"
#include "onic_xsk.h"
#include "onic_lib.h"



/**
 * onic_xsk_pool_setup - Enable or disable XSK pool
 * @priv: pointer to onic_private
 * @pool: buffer pool to enable/associate, NULL to disable
 * @qid: Rx ring to operate on
 * 
 * return 0 on success, negative on failure
 */



static int onic_xsk_wakeup(struct net_device *dev, u16 qid, u32 flags){
    return -1;
}


static int onic_xsk_pool_enable(struct onic_private *priv, struct xsk_buff_pool *pool, u16 qid){

    int err;
    bool if_running;
    
    if (qid >= priv->num_rx_queues || qid >= priv->num_tx_queues)
        return -EINVAL;
    
    
    err = xsk_pool_dma_map(pool, &priv->pdev->dev,  DMA_ATTR_SKIP_CPU_SYNC);
    if (err)
        return err;
    
    set_bit(qid, priv->af_xdp_zc_qps);


	if_running = netif_running(priv->netdev);

	if (if_running) {
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

int onic_xsk_pool_setup(struct onic_private *priv, struct xsk_buff_pool *pool, u16 qid){

    return pool = onic_xsk_pool_enable(priv, pool, qid) : onic_xsk_pool_disable(priv, qid);
}
