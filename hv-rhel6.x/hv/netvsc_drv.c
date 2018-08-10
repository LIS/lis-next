/*
 * Copyright (c) 2009, Microsoft Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *   Haiyang Zhang <haiyangz@microsoft.com>
 *   Hank Janssen  <hjanssen@microsoft.com>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/ipv6.h>
#include <net/arp.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/pkt_sched.h>
#include <net/checksum.h>
#include <net/ip6_checksum.h>
#include <linux/rtnetlink.h>

#include "include/linux/hyperv.h"
#include "hyperv_net.h"

#define RING_SIZE_MIN 64
#define LINKCHANGE_INT (2 * HZ)

static int ring_size = 128;
module_param(ring_size, int, 0444);
MODULE_PARM_DESC(ring_size, "Ring buffer size (# of pages)");

static const u32 default_msg = NETIF_MSG_DRV | NETIF_MSG_PROBE |
		NETIF_MSG_LINK | NETIF_MSG_IFUP |
		NETIF_MSG_IFDOWN | NETIF_MSG_RX_ERR |
		NETIF_MSG_TX_ERR;

static int debug = -1;
module_param(debug, int, 0444);
MODULE_PARM_DESC(debug, "Debug level (0=none,...,16=all)");

static void netvsc_set_multicast_list(struct net_device *net)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);
	struct netvsc_device *nvdev = rtnl_dereference(net_device_ctx->nvdev);

	rndis_filter_update(nvdev);
}

static int netvsc_open(struct net_device *net)
{
	struct net_device_context *ndev_ctx = netdev_priv(net);
	struct netvsc_device *nvdev = ndev_ctx->nvdev;
	struct rndis_device *rdev;
	int ret = 0;

	netif_carrier_off(net);

	/* Open up the device */
	ret = rndis_filter_open(nvdev);
	if (ret != 0) {
		netdev_err(net, "unable to open device (ret %d).\n", ret);
		return ret;
	}

	netif_tx_wake_all_queues(net);

	rdev = nvdev->extension;
	if (!rdev->link_state && !ndev_ctx->datapath)
		netif_carrier_on(net);

	return ret;
}

static int netvsc_close(struct net_device *net)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);
	struct netvsc_device *nvdev = net_device_ctx->nvdev;
	int ret = 0;
	u32 aread, i, msec = 10, retry = 0, retry_max = 20;
	struct vmbus_channel *chn;

	netif_tx_disable(net);

	/* No need to close rndis filter if it is removed already */
	if (!nvdev)
		goto out;

	ret = rndis_filter_close(nvdev);
	if (ret != 0) {
		netdev_err(net, "unable to close device (ret %d).\n", ret);
		return ret;
	}

	/* Ensure pending bytes in ring are read */
	while (true) {
		aread = 0;
		for (i = 0; i < nvdev->num_chn; i++) {
			chn = nvdev->chan_table[i].channel;
			if (!chn)
				continue;

			aread = hv_get_bytes_to_read(&chn->inbound);
			if (aread)
				break;

			aread = hv_get_bytes_to_read(&chn->outbound);
			if (aread)
				break;
		}

		retry++;
		if (retry > retry_max || aread == 0)
			break;

		msleep(msec);

		if (msec < 1000)
			msec *= 2;
	}

	if (aread) {
		netdev_err(net, "Ring buffer not empty after closing rndis\n");
		ret = -ETIMEDOUT;
	}

out:
	return ret;
}

static void *init_ppi_data(struct rndis_message *msg, u32 ppi_size,
				int pkt_type)
{
	struct rndis_packet *rndis_pkt;
	struct rndis_per_packet_info *ppi;

	rndis_pkt = &msg->msg.pkt;
	rndis_pkt->data_offset += ppi_size;

	ppi = (struct rndis_per_packet_info *)((void *)rndis_pkt +
		rndis_pkt->per_pkt_info_offset + rndis_pkt->per_pkt_info_len);

	ppi->size = ppi_size;
	ppi->type = pkt_type;
	ppi->ppi_offset = sizeof(struct rndis_per_packet_info);

	rndis_pkt->per_pkt_info_len += ppi_size;

	return ppi;
}

#ifdef NOTYET
// Divergence from upstream commit:
// 5b54dac856cb5bd6f33f4159012773e4a33704f7
static u16 netvsc_select_queue(struct net_device *ndev, struct sk_buff *skb,
			void *accel_priv, select_queue_fallback_t fallback)
#endif
static u16 netvsc_select_queue(struct net_device *ndev, struct sk_buff *skb)
{
	struct net_device_context *net_device_ctx = netdev_priv(ndev);
	u32 hash;
	u16 q_idx = 0;

	if (ndev->real_num_tx_queues <= 1)
		return 0;

	hash = skb_get_hash(skb);
	q_idx = net_device_ctx->tx_send_table[hash % VRSS_SEND_TAB_SIZE] %
		ndev->real_num_tx_queues;

	return q_idx;
}

static u32 fill_pg_buf(struct page *page, u32 offset, u32 len,
			struct hv_page_buffer *pb)
{
	int j = 0;

	/* Deal with compund pages by ignoring unused part
	 * of the page.
	 */
	page += (offset >> PAGE_SHIFT);
	offset &= ~PAGE_MASK;

	while (len > 0) {
		unsigned long bytes;

		bytes = PAGE_SIZE - offset;
		if (bytes > len)
			bytes = len;
		pb[j].pfn = page_to_pfn(page);
		pb[j].offset = offset;
		pb[j].len = bytes;

		offset += bytes;
		len -= bytes;

		if (offset == PAGE_SIZE && len) {
			page++;
			offset = 0;
			j++;
		}
	}

	return j + 1;
}

static u32 init_page_array(void *hdr, u32 len, struct sk_buff *skb,
			   struct hv_netvsc_packet *packet,
			   struct hv_page_buffer **page_buf)
{
	struct hv_page_buffer *pb = *page_buf;
	u32 slots_used = 0;
	char *data = skb->data;
	int frags = skb_shinfo(skb)->nr_frags;
	int i;

	/* The packet is laid out thus:
	 * 1. hdr: RNDIS header and PPI
	 * 2. skb linear data
	 * 3. skb fragment data
	 */
	if (hdr != NULL)
		slots_used += fill_pg_buf(virt_to_page(hdr),
					offset_in_page(hdr),
					len, &pb[slots_used]);

	packet->rmsg_size = len;
	packet->rmsg_pgcnt = slots_used;

	slots_used += fill_pg_buf(virt_to_page(data),
				offset_in_page(data),
				skb_headlen(skb), &pb[slots_used]);

	for (i = 0; i < frags; i++) {
		skb_frag_t *frag = skb_shinfo(skb)->frags + i;

		slots_used += fill_pg_buf(skb_frag_page(frag),
					frag->page_offset,
					skb_frag_size(frag), &pb[slots_used]);
	}
	return slots_used;
}

static int count_skb_frag_slots(struct sk_buff *skb)
{
	int i, frags = skb_shinfo(skb)->nr_frags;
	int pages = 0;

	for (i = 0; i < frags; i++) {
		skb_frag_t *frag = skb_shinfo(skb)->frags + i;
		unsigned long size = skb_frag_size(frag);
		unsigned long offset = frag->page_offset;

		/* Skip unused frames from start of page */
		offset &= ~PAGE_MASK;
		pages += PFN_UP(offset + size);
	}
	return pages;
}

static int netvsc_get_slots(struct sk_buff *skb)
{
	char *data = skb->data;
	unsigned int offset = offset_in_page(data);
	unsigned int len = skb_headlen(skb);
	int slots;
	int frag_slots;

	slots = DIV_ROUND_UP(offset + len, PAGE_SIZE);
	frag_slots = count_skb_frag_slots(skb);
	return slots + frag_slots;
}

static u32 net_checksum_info(struct sk_buff *skb)
{
	skb_reset_mac_header(skb);  //NHM - is this needed?

	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *ip = ip_hdr(skb);

		if (ip->protocol == IPPROTO_TCP)
			return TRANSPORT_INFO_IPV4_TCP;
		else if (ip->protocol == IPPROTO_UDP)
			return TRANSPORT_INFO_IPV4_UDP;
	} else {
		struct ipv6hdr *ip6 = ipv6_hdr(skb);

		if (ip6->nexthdr == IPPROTO_TCP)
			return TRANSPORT_INFO_IPV6_TCP;
		else if (ip6->nexthdr == IPPROTO_UDP)
			return TRANSPORT_INFO_IPV6_UDP;
	}

	return TRANSPORT_INFO_NOT_IP;
}

static int netvsc_start_xmit(struct sk_buff *skb, struct net_device *net)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);
	struct hv_netvsc_packet *packet = NULL;
	int ret;
	unsigned int num_data_pgs;
	struct rndis_message *rndis_msg;
	struct rndis_packet *rndis_pkt;
	u32 rndis_msg_size;
	struct rndis_per_packet_info *ppi;
	u32 hash;
	struct hv_page_buffer page_buf[MAX_PAGE_BUFFER_COUNT];
	struct hv_page_buffer *pb = page_buf;

	/* We will atmost need two pages to describe the rndis
	 * header. We can only transmit MAX_PAGE_BUFFER_COUNT number
	 * of pages in a single packet. If skb is scattered around
	 * more pages we try linearizing it.
	 */

	num_data_pgs = netvsc_get_slots(skb) + 2;

	if (unlikely(num_data_pgs > MAX_PAGE_BUFFER_COUNT)) {
		++net_device_ctx->eth_stats.tx_scattered;

		if (skb_linearize(skb))
			goto no_memory;

		num_data_pgs = netvsc_get_slots(skb) + 2;
		if (num_data_pgs > MAX_PAGE_BUFFER_COUNT) {
			++net_device_ctx->eth_stats.tx_too_big;
			goto drop;
		}
	}

	/*
	 * Place the rndis header in the skb head room and
	 * the skb->cb will be used for hv_netvsc_packet
	 * structure.
	 */
	ret = skb_cow_head(skb, RNDIS_AND_PPI_SIZE);
	if (ret)
		goto no_memory;

	/* Use the skb control buffer for building up the packet */
	BUILD_BUG_ON(sizeof(struct hv_netvsc_packet) >
			FIELD_SIZEOF(struct sk_buff, cb));
	packet = (struct hv_netvsc_packet *)skb->cb;

	/* TODO: This will likely evaluate to false, since RH7 and
	 * below kernels will set next pointer to NULL before calling
	 * into here. Should find another way to set this flag.
	 */
	packet->xmit_more = (skb->next != NULL);

	packet->q_idx = skb_get_queue_mapping(skb);

	packet->total_data_buflen = skb->len;
	packet->total_bytes = skb->len;
	packet->total_packets = 1;

	rndis_msg = (struct rndis_message *)skb->head;

	memset(rndis_msg, 0, RNDIS_AND_PPI_SIZE);

	packet->send_completion_ctx = packet;

	/* Add the rndis header */
	rndis_msg->ndis_msg_type = RNDIS_MSG_PACKET;
	rndis_msg->msg_len = packet->total_data_buflen;
	rndis_pkt = &rndis_msg->msg.pkt;
	rndis_pkt->data_offset = sizeof(struct rndis_packet);
	rndis_pkt->data_len = packet->total_data_buflen;
	rndis_pkt->per_pkt_info_offset = sizeof(struct rndis_packet);

	rndis_msg_size = RNDIS_MESSAGE_SIZE(struct rndis_packet);

#ifdef NOTYET
	// Divergence from upstream commit:
	// 307f099520b66504cf6c5638f3f404c48b9fb45b
	hash = skb_get_hash_raw(skb);
#endif
	hash = skb_get_hash(skb);
	if (hash != 0 && net->real_num_tx_queues > 1) {
		rndis_msg_size += NDIS_HASH_PPI_SIZE;
		ppi = init_ppi_data(rndis_msg, NDIS_HASH_PPI_SIZE,
				    NBL_HASH_VALUE);
		*(u32 *)((void *)ppi + ppi->ppi_offset) = hash;
	}

	if (skb_vlan_tag_present(skb)) {
		struct ndis_pkt_8021q_info *vlan;

		rndis_msg_size += NDIS_VLAN_PPI_SIZE;
		ppi = init_ppi_data(rndis_msg, NDIS_VLAN_PPI_SIZE,
					IEEE_8021Q_INFO);
		vlan = (struct ndis_pkt_8021q_info *)((void *)ppi +
						ppi->ppi_offset);
		vlan->vlanid = skb->vlan_tci & VLAN_VID_MASK;
		vlan->pri = (skb->vlan_tci & VLAN_PRIO_MASK) >>
				VLAN_PRIO_SHIFT;
	}

	if (skb_is_gso(skb)) {
		struct ndis_tcp_lso_info *lso_info;

		rndis_msg_size += NDIS_LSO_PPI_SIZE;
		ppi = init_ppi_data(rndis_msg, NDIS_LSO_PPI_SIZE,
				    TCP_LARGESEND_PKTINFO);

		lso_info = (struct ndis_tcp_lso_info *)((void *)ppi +
							ppi->ppi_offset);

		lso_info->lso_v2_transmit.type = NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE;
		if (skb->protocol == htons(ETH_P_IP)) {
			lso_info->lso_v2_transmit.ip_version =
				NDIS_TCP_LARGE_SEND_OFFLOAD_IPV4;
			ip_hdr(skb)->tot_len = 0;
			ip_hdr(skb)->check = 0;
			tcp_hdr(skb)->check =
				~csum_tcpudp_magic(ip_hdr(skb)->saddr,
						   ip_hdr(skb)->daddr, 0, IPPROTO_TCP, 0);
		} else {
			lso_info->lso_v2_transmit.ip_version =
				NDIS_TCP_LARGE_SEND_OFFLOAD_IPV6;
			ipv6_hdr(skb)->payload_len = 0;
			tcp_hdr(skb)->check =
				~csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
						 &ipv6_hdr(skb)->daddr, 0, IPPROTO_TCP, 0);
		}
		lso_info->lso_v2_transmit.tcp_header_offset = skb_transport_offset(skb);
		lso_info->lso_v2_transmit.mss = skb_shinfo(skb)->gso_size;
	} else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (net_checksum_info(skb) & net_device_ctx->tx_checksum_mask) {
			struct ndis_tcp_ip_checksum_info *csum_info;

			rndis_msg_size += NDIS_CSUM_PPI_SIZE;
			ppi = init_ppi_data(rndis_msg, NDIS_CSUM_PPI_SIZE,
					    TCPIP_CHKSUM_PKTINFO);

			csum_info = (struct ndis_tcp_ip_checksum_info *)((void *)ppi +
									 ppi->ppi_offset);

			csum_info->transmit.tcp_header_offset = skb_transport_offset(skb);

			if (skb->protocol == htons(ETH_P_IP)) {
				csum_info->transmit.is_ipv4 = 1;

				if (ip_hdr(skb)->protocol == IPPROTO_TCP)
					csum_info->transmit.tcp_checksum = 1;
				else
					csum_info->transmit.udp_checksum = 1;
			} else {
				csum_info->transmit.is_ipv6 = 1;

				if (ipv6_hdr(skb)->nexthdr == IPPROTO_TCP)
					csum_info->transmit.tcp_checksum = 1;
				else
					csum_info->transmit.udp_checksum = 1;
			}
		} else {
			/* Can't do offload of this type of checksum */
			if (skb_checksum_help(skb))
				goto drop;
		}
	}

	/* Start filling in the page buffers with the rndis hdr */
	rndis_msg->msg_len += rndis_msg_size;
	packet->total_data_buflen = rndis_msg->msg_len;
	packet->page_buf_cnt = init_page_array(rndis_msg, rndis_msg_size,
					       skb, packet, &pb);

#if defined(RHEL_RELEASE_VERSION) && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,3))
	/* timestamp packet in software */
	skb_tx_timestamp(skb);
#endif

	ret = netvsc_send(net_device_ctx, packet, rndis_msg, &pb, skb);
	if (likely(ret == 0))
		return NETDEV_TX_OK;

	if (ret == -EAGAIN) {
		++net_device_ctx->eth_stats.tx_busy;
		return NETDEV_TX_BUSY;
	}
drop:
	dev_kfree_skb_any(skb);
	net->stats.tx_dropped++;

	return NETDEV_TX_OK;

no_memory:
	++net_device_ctx->eth_stats.tx_no_memory;
	goto drop;
}

/*
 * netvsc_linkstatus_callback - Link up/down notification
 */
void netvsc_linkstatus_callback(struct hv_device *device_obj,
				struct rndis_message *resp)
{
	struct rndis_indicate_status *indicate = &resp->msg.indicate_status;
	struct net_device *net;
	struct net_device_context *ndev_ctx;
	struct netvsc_reconfig *event;
	unsigned long flags;

	net = hv_get_drvdata(device_obj);

	if (!net)
		return;

	ndev_ctx = netdev_priv(net);

	/* Update the physical link speed when changing to another vSwitch */
	if (indicate->status == RNDIS_STATUS_LINK_SPEED_CHANGE) {
		u32 speed;

		speed = *(u32 *)((void *)indicate + indicate->
				 status_buf_offset) / 10000;
		ndev_ctx->speed = speed;
		return;
	}

	/* Handle these link change statuses below */
	if (indicate->status != RNDIS_STATUS_NETWORK_CHANGE &&
	    indicate->status != RNDIS_STATUS_MEDIA_CONNECT &&
	    indicate->status != RNDIS_STATUS_MEDIA_DISCONNECT)
		return;

	if (net->reg_state != NETREG_REGISTERED)
		return;

	event = kzalloc(sizeof(*event), GFP_ATOMIC);
	if (!event)
		return;
	event->event = indicate->status;

	spin_lock_irqsave(&ndev_ctx->lock, flags);
	list_add_tail(&event->list, &ndev_ctx->reconfig_events);
	spin_unlock_irqrestore(&ndev_ctx->lock, flags);

	schedule_delayed_work(&ndev_ctx->dwork, 0);
}

static struct sk_buff *netvsc_alloc_recv_skb(struct net_device *net,
					     const struct ndis_tcp_ip_checksum_info *csum_info,
					     const struct ndis_pkt_8021q_info *vlan,
					     void *data, u32 buflen)
{
	struct sk_buff *skb;

	skb = netdev_alloc_skb_ip_align(net, buflen);
	if (!skb)
		return skb;

	/*
	 * Copy to skb. This copy is needed here since the memory pointed by
	 * hv_netvsc_packet cannot be deallocated
	 */
	memcpy(skb_put(skb, buflen), data, buflen);

	skb->protocol = eth_type_trans(skb, net);

	/* skb is already created with CHECKSUM_NONE */
	skb_checksum_none_assert(skb);

	/*
	 * In Linux, the IP checksum is always checked.
	 * Do L4 checksum offload if enabled and present.
	 */
	if (csum_info && (net->features & NETIF_F_RXCSUM)) {
		if (csum_info->receive.tcp_checksum_succeeded ||
		    csum_info->receive.udp_checksum_succeeded)
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}

	if (vlan) {
		u16 vlan_tci = vlan->vlanid | (vlan->pri << VLAN_PRIO_SHIFT);

		__vlan_hwaccel_put_tag(skb, vlan_tci);
	}

	return skb;
}

/*
 * netvsc_recv_callback -  Callback when we receive a packet from the
 * "wire" on the specified device.
 */
int netvsc_recv_callback(struct net_device *net,
			 struct vmbus_channel *channel,
			 void  *data, u32 len,
			 const struct ndis_tcp_ip_checksum_info *csum_info,
			 const struct ndis_pkt_8021q_info *vlan)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);
	struct netvsc_device *net_device = net_device_ctx->nvdev;
	u16 q_idx = channel->offermsg.offer.sub_channel_index;
	struct netvsc_channel *nvchan = &net_device->chan_table[q_idx];
	struct sk_buff *skb;
	struct sk_buff *vf_skb;
	struct netvsc_stats *rx_stats;
	int ret = 0;

	if (!net || net->reg_state != NETREG_REGISTERED)
		return NVSP_STAT_FAIL;

	if (READ_ONCE(net_device_ctx->vf_inject)) {
		atomic_inc(&net_device_ctx->vf_use_cnt);
		if (!READ_ONCE(net_device_ctx->vf_inject)) {
			/*
			 * We raced; just move on.
			 */
			atomic_dec(&net_device_ctx->vf_use_cnt);
			goto vf_injection_done;
		}

		/*
		 * Inject this packet into the VF inerface.
		 * On Hyper-V, multicast and brodcast packets
		 * are only delivered on the synthetic interface
		 * (after subjecting these to policy filters on
		 * the host). Deliver these via the VF interface
		 * in the guest.
		 */
		vf_skb = netvsc_alloc_recv_skb(net_device_ctx->vf_netdev,
					       csum_info, vlan, data, len);
		if (vf_skb != NULL) {
			++net_device_ctx->vf_netdev->stats.rx_packets;
			net_device_ctx->vf_netdev->stats.rx_bytes +=
				len;
			netif_receive_skb(vf_skb);
		} else {
			++net->stats.rx_dropped;
			ret = NVSP_STAT_FAIL;
		}
		atomic_dec(&net_device_ctx->vf_use_cnt);
		return ret;
	}

vf_injection_done:
	rx_stats = &nvchan->rx_stats;

	/* Allocate a skb - TODO direct I/O to pages? */
	skb = netvsc_alloc_recv_skb(net, csum_info, vlan, data, len);
	if (unlikely(!skb)) {
		++net->stats.rx_dropped;
		return NVSP_STAT_FAIL;
	}
	skb_record_rx_queue(skb, q_idx);

	u64_stats_update_begin(&rx_stats->syncp);
	rx_stats->packets++;
	rx_stats->bytes += len;

	if (skb->pkt_type == PACKET_BROADCAST)
		++rx_stats->broadcast;
	else if (skb->pkt_type == PACKET_MULTICAST)
		++rx_stats->multicast;
	u64_stats_update_end(&rx_stats->syncp);

	net->stats.rx_packets++;
	net->stats.rx_bytes += len;

	napi_gro_receive(&nvchan->napi, skb);
	return NVSP_STAT_SUCCESS;
}

static void netvsc_get_drvinfo(struct net_device *net,
			       struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, KBUILD_MODNAME, sizeof(info->driver));
	strlcpy(info->fw_version, "N/A", sizeof(info->fw_version));
}

#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,0))
static void netvsc_get_channels(struct net_device *net,
				struct ethtool_channels *channel)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);
	struct netvsc_device *nvdev = net_device_ctx->nvdev;

	if (nvdev) {
		channel->max_combined	= nvdev->max_chn;
		channel->combined_count = nvdev->num_chn;
	}
}

static int netvsc_set_channels(struct net_device *net,
			       struct ethtool_channels *channels)
{
	struct net_device_context *net_device_ctx = netdev_priv(net);
	struct hv_device *dev = net_device_ctx->device_ctx;
	struct netvsc_device *nvdev = net_device_ctx->nvdev;
	unsigned int orig, count = channels->combined_count;
	struct netvsc_device_info device_info;
	bool was_opened;
	int ret = 0;

	/* We do not support separate count for rx, tx, or other */
	if (count == 0 ||
	    channels->rx_count || channels->tx_count || channels->other_count)
		return -EINVAL;

	if (count > net->num_tx_queues || count > VRSS_CHANNEL_MAX)
		return -EINVAL;

	if (!nvdev || nvdev->destroy)
		return -ENODEV;

	if (nvdev->nvsp_version < NVSP_PROTOCOL_VERSION_5)
		return -EINVAL;

	if (count > nvdev->max_chn)
		return -EINVAL;
	orig = nvdev->num_chn;

	was_opened = rndis_filter_opened(nvdev);
	if (was_opened)
		rndis_filter_close(nvdev);

	rndis_filter_device_remove(dev, nvdev);

	memset(&device_info, 0, sizeof(device_info));
	device_info.num_chn = count;
	device_info.ring_size = ring_size;

	nvdev = rndis_filter_device_add(dev, &device_info);
	if (IS_ERR(nvdev)) {
		device_info.num_chn = orig;
		rndis_filter_device_add(dev, &device_info);
	}

	if (was_opened)
		rndis_filter_open(nvdev);

	/* We may have missed link change notifications */
	net_device_ctx->last_reconfig = 0;
	schedule_delayed_work(&net_device_ctx->dwork, 0);

	return ret;
}
#endif

static bool netvsc_validate_ethtool_ss_cmd(const struct ethtool_cmd *cmd)
{
	struct ethtool_cmd diff1 = *cmd;
	struct ethtool_cmd diff2 = {};

	ethtool_cmd_speed_set(&diff1, 0);
	diff1.duplex = 0;
	/* advertising and cmd are usually set */
	diff1.advertising = 0;
	diff1.cmd = 0;
	/* We set port to PORT_OTHER */
	diff2.port = PORT_OTHER;

	return !memcmp(&diff1, &diff2, sizeof(diff1));
}

static void netvsc_init_settings(struct net_device *dev)
{
	struct net_device_context *ndc = netdev_priv(dev);

	ndc->speed = SPEED_UNKNOWN;
	ndc->duplex = DUPLEX_FULL;
}

static int netvsc_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct net_device_context *ndc = netdev_priv(dev);

	ethtool_cmd_speed_set(cmd, ndc->speed);
	cmd->duplex = ndc->duplex;
	cmd->port = PORT_OTHER;

	return 0;
}

static int netvsc_set_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct net_device_context *ndc = netdev_priv(dev);
	u32 speed;

	speed = ethtool_cmd_speed(cmd);
	if (!ethtool_validate_speed(speed) ||
	    !ethtool_validate_duplex(cmd->duplex) ||
	    !netvsc_validate_ethtool_ss_cmd(cmd))
		return -EINVAL;

	ndc->speed = speed;
	ndc->duplex = cmd->duplex;

	return 0;
}

static int netvsc_change_mtu(struct net_device *ndev, int mtu)
{
	struct net_device_context *ndevctx = netdev_priv(ndev);
	struct netvsc_device *nvdev = ndevctx->nvdev;
	struct hv_device *hdev = ndevctx->device_ctx;
	int orig_mtu = ndev->mtu;
	struct netvsc_device_info device_info;
	int limit = ETH_DATA_LEN;
	bool was_opened;
	int ret = 0;

	if (!nvdev || nvdev->destroy)
		return -ENODEV;

	if (nvdev->nvsp_version >= NVSP_PROTOCOL_VERSION_2)
		limit = NETVSC_MTU - ETH_HLEN;

	if (mtu < NETVSC_MTU_MIN || mtu > limit)
		return -EINVAL;

	netif_device_detach(ndev);
	was_opened = rndis_filter_opened(nvdev);
	if (was_opened)
		rndis_filter_close(nvdev);

	memset(&device_info, 0, sizeof(device_info));
	device_info.ring_size = ring_size;
	device_info.num_chn = nvdev->num_chn;

	rndis_filter_device_remove(hdev, nvdev);

	ndev->mtu = mtu;

	nvdev = rndis_filter_device_add(hdev, &device_info);
	if (IS_ERR(nvdev)) {
		ret = PTR_ERR(nvdev);

		/* Attempt rollback to original MTU */
		ndev->mtu = orig_mtu;
		rndis_filter_device_add(hdev, &device_info);
	}

	if (was_opened)
		rndis_filter_open(nvdev);

	netif_device_attach(ndev);

	/* We may have missed link change notifications */
	schedule_delayed_work(&ndevctx->dwork, 0);

	return ret;
}

#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,0))
static void *netvsc_get_stats64(struct net_device *net,
				struct rtnl_link_stats64 *t)
{
	struct net_device_context *ndev_ctx = netdev_priv(net);
	struct netvsc_device *nvdev = rcu_dereference_rtnl(ndev_ctx->nvdev);
	int i;

	if (!nvdev)
		return;

	for (i = 0; i < nvdev->num_chn; i++) {
		const struct netvsc_channel *nvchan = &nvdev->chan_table[i];
		const struct netvsc_stats *stats;
		u64 packets, bytes, multicast;
		unsigned int start;

		stats = &nvchan->tx_stats;
		do {
			start = u64_stats_fetch_begin_irq(&stats->syncp);
			packets = stats->packets;
			bytes = stats->bytes;
		} while (u64_stats_fetch_retry_irq(&stats->syncp, start));

		t->tx_bytes	+= bytes;
		t->tx_packets	+= packets;

		stats = &nvchan->rx_stats;
		do {
			start = u64_stats_fetch_begin_irq(&stats->syncp);
			packets = stats->packets;
			bytes = stats->bytes;
			multicast = stats->multicast + stats->broadcast;
		} while (u64_stats_fetch_retry_irq(&stats->syncp, start));

		t->rx_bytes	+= bytes;
		t->rx_packets	+= packets;
		t->multicast	+= multicast;
	}

	t->tx_dropped	= net->stats.tx_dropped;
	t->tx_errors	= net->stats.tx_errors;

	t->rx_dropped	= net->stats.rx_dropped;
	t->rx_errors	= net->stats.rx_errors;
}
#endif

static int netvsc_set_mac_addr(struct net_device *ndev, void *p)
{
	struct sockaddr *addr = p;
	char save_adr[ETH_ALEN];
	unsigned char save_aatype;
	int err;

	memcpy(save_adr, ndev->dev_addr, ETH_ALEN);
	save_aatype = ndev->addr_assign_type;

	err = eth_mac_addr(ndev, p);
	if (err != 0)
		return err;

	err = rndis_filter_set_device_mac(ndev, addr->sa_data);
	if (err != 0) {
		/* roll back to saved MAC */
		memcpy(ndev->dev_addr, save_adr, ETH_ALEN);
		ndev->addr_assign_type = save_aatype;
	}

	return err;
}

static const struct {
	char name[ETH_GSTRING_LEN];
	u16 offset;
} netvsc_stats[] = {
	{ "tx_scattered", offsetof(struct netvsc_ethtool_stats, tx_scattered) },
	{ "tx_no_memory",  offsetof(struct netvsc_ethtool_stats, tx_no_memory) },
	{ "tx_no_space",  offsetof(struct netvsc_ethtool_stats, tx_no_space) },
	{ "tx_too_big",	  offsetof(struct netvsc_ethtool_stats, tx_too_big) },
	{ "tx_busy",	  offsetof(struct netvsc_ethtool_stats, tx_busy) },
	{ "stop_queue", offsetof(struct netvsc_ethtool_stats, stop_queue) },
	{ "wake_queue", offsetof(struct netvsc_ethtool_stats, wake_queue) },
};

#define NETVSC_GLOBAL_STATS_LEN	ARRAY_SIZE(netvsc_stats)

/* 4 statistics per queue (rx/tx packets/bytes) */
#define NETVSC_QUEUE_STATS_LEN(dev) ((dev)->num_chn * 4)

static int netvsc_get_sset_count(struct net_device *dev, int string_set)
{
	struct net_device_context *ndc = netdev_priv(dev);
	struct netvsc_device *nvdev = rtnl_dereference(ndc->nvdev);

	if (!nvdev)
		return -ENODEV;

	switch (string_set) {
	case ETH_SS_STATS:
		return NETVSC_GLOBAL_STATS_LEN + NETVSC_QUEUE_STATS_LEN(nvdev);
	default:
		return -EINVAL;
	}
}

static void netvsc_get_ethtool_stats(struct net_device *dev,
				     struct ethtool_stats *stats, u64 *data)
{
	struct net_device_context *ndc = netdev_priv(dev);
	struct netvsc_device *nvdev = ndc->nvdev;
	const void *nds = &ndc->eth_stats;
	const struct netvsc_stats *qstats;
	unsigned int start;
	u64 packets, bytes;
	int i, j;

	for (i = 0; i < NETVSC_GLOBAL_STATS_LEN; i++)
		data[i] = *(unsigned long *)(nds + netvsc_stats[i].offset);

	for (j = 0; j < nvdev->num_chn; j++) {
		qstats = &nvdev->chan_table[j].tx_stats;

		do {
			start = u64_stats_fetch_begin_irq(&qstats->syncp);
			packets = qstats->packets;
			bytes = qstats->bytes;
		} while (u64_stats_fetch_retry_irq(&qstats->syncp, start));
		data[i++] = packets;
		data[i++] = bytes;

		qstats = &nvdev->chan_table[j].rx_stats;
		do {
			start = u64_stats_fetch_begin_irq(&qstats->syncp);
			packets = qstats->packets;
			bytes = qstats->bytes;
		} while (u64_stats_fetch_retry_irq(&qstats->syncp, start));
		data[i++] = packets;
		data[i++] = bytes;
	}
}

static void netvsc_get_strings(struct net_device *dev, u32 stringset, u8 *data)
{
	struct net_device_context *ndc = netdev_priv(dev);
	struct netvsc_device *nvdev = ndc->nvdev;
	u8 *p = data;
	int i;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < ARRAY_SIZE(netvsc_stats); i++)
			memcpy(p + i * ETH_GSTRING_LEN,
			       netvsc_stats[i].name, ETH_GSTRING_LEN);

		p += i * ETH_GSTRING_LEN;
		for (i = 0; i < nvdev->num_chn; i++) {
			sprintf(p, "tx_queue_%u_packets", i);
			p += ETH_GSTRING_LEN;
			sprintf(p, "tx_queue_%u_bytes", i);
			p += ETH_GSTRING_LEN;
			sprintf(p, "rx_queue_%u_packets", i);
			p += ETH_GSTRING_LEN;
			sprintf(p, "rx_queue_%u_bytes", i);
			p += ETH_GSTRING_LEN;
		}

		break;
	}
}

static int
netvsc_get_rss_hash_opts(struct netvsc_device *nvdev,
			 struct ethtool_rxnfc *info)
{
	info->data = RXH_IP_SRC | RXH_IP_DST;

	switch (info->flow_type) {
	case TCP_V4_FLOW:
	case TCP_V6_FLOW:
		info->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;
		/* fallthrough */
	case UDP_V4_FLOW:
	case UDP_V6_FLOW:
#ifdef NOTYET
	case IPV4_FLOW:
	case IPV6_FLOW:
#endif
		break;
	default:
		info->data = 0;
		break;
	}

	return 0;
}

#ifdef NOTYET
static int
netvsc_get_rxnfc(struct net_device *dev, struct ethtool_rxnfc *info,
		 u32 *rules)
#endif
static int
netvsc_get_rxnfc(struct net_device *dev, struct ethtool_rxnfc *info,
		 void *rules)

{
	struct net_device_context *ndc = netdev_priv(dev);
	struct netvsc_device *nvdev = ndc->nvdev;

	switch (info->cmd) {
	case ETHTOOL_GRXRINGS:
		info->data = nvdev->num_chn;
		return 0;

	case ETHTOOL_GRXFH:
		return netvsc_get_rss_hash_opts(nvdev, info);
	}
	return -EOPNOTSUPP;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void netvsc_poll_controller(struct net_device *dev)
{
	struct net_device_context *ndc = netdev_priv(dev);
	struct netvsc_device *ndev;
	int i;

	rcu_read_lock();
	ndev = rcu_dereference(ndc->nvdev);
	if (ndev) {
		for (i = 0; i < ndev->num_chn; i++) {
			struct netvsc_channel *nvchan = &ndev->chan_table[i];

			napi_schedule(&nvchan->napi);
		}
	}
	rcu_read_unlock();
}
#endif

#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,10))
static u32 netvsc_get_rxfh_key_size(struct net_device *dev)
{
	return NETVSC_HASH_KEYLEN;
}

static u32 netvsc_rss_indir_size(struct net_device *dev)
{
	return ITAB_NUM;
}

static int netvsc_get_rxfh(struct net_device *dev, u32 *indir, u8 *key,
			   u8 *hfunc)
{
	struct net_device_context *ndc = netdev_priv(dev);
	struct netvsc_device *ndev = ndc->nvdev;
	struct rndis_device *rndis_dev;
	int i;

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;	/* Toeplitz */

	rndis_dev = ndev->extension;
	if (indir) {
		for (i = 0; i < ITAB_NUM; i++)
			indir[i] = rndis_dev->ind_table[i];
	}

	if (key)
		memcpy(key, rndis_dev->rss_key, NETVSC_HASH_KEYLEN);

	return 0;
}

static int netvsc_set_rxfh(struct net_device *dev, const u32 *indir,
			   const u8 *key, const u8 hfunc)
{
	struct net_device_context *ndc = netdev_priv(dev);
	struct netvsc_device *ndev = ndc->nvdev;
	struct rndis_device *rndis_dev;
	int i;

	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;

	rndis_dev = ndev->extension;
	if (indir) {
		for (i = 0; i < ITAB_NUM; i++)
			if (indir[i] >= VRSS_CHANNEL_MAX)
				return -EINVAL;

		for (i = 0; i < ITAB_NUM; i++)
			rndis_dev->ind_table[i] = indir[i];
	}

	if (!key) {
		if (!indir)
			return 0;

		key = rndis_dev->rss_key;
	}

	return rndis_filter_set_rss_param(rndis_dev, key, ndev->num_chn);
}
#endif

static const struct ethtool_ops ethtool_ops = {
	.get_drvinfo	= netvsc_get_drvinfo,
	.get_link	= ethtool_op_get_link,
	.get_ethtool_stats = netvsc_get_ethtool_stats,
	.get_sset_count = netvsc_get_sset_count,
	.get_strings	= netvsc_get_strings,
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,0))
	.get_channels   = netvsc_get_channels,
	.set_channels   = netvsc_set_channels,
	.get_ts_info	= ethtool_op_get_ts_info,
#endif
	.get_settings	= netvsc_get_settings,
	.set_settings	= netvsc_set_settings,
	.get_rxnfc	= netvsc_get_rxnfc,
#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,10))
	.get_rxfh_key_size = netvsc_get_rxfh_key_size,
	.get_rxfh_indir_size = netvsc_rss_indir_size,
	.get_rxfh	= netvsc_get_rxfh,
	.set_rxfh	= netvsc_set_rxfh,
#endif
};

static const struct net_device_ops device_ops = {
	.ndo_open =			netvsc_open,
	.ndo_stop =			netvsc_close,
	.ndo_start_xmit =		netvsc_start_xmit,
	.ndo_set_rx_mode =		netvsc_set_multicast_list,
	.ndo_change_mtu =		netvsc_change_mtu,
	.ndo_validate_addr =		eth_validate_addr,
	.ndo_set_mac_address =		netvsc_set_mac_addr,
	.ndo_select_queue =		netvsc_select_queue,
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,0))
	.ndo_get_stats64 =		netvsc_get_stats64,
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller =		netvsc_poll_controller,
#endif
};

/*
 * Handle link status changes. For RNDIS_STATUS_NETWORK_CHANGE emulate link
 * down/up sequences. In case of RNDIS_STATUS_MEDIA_CONNECT when carrier is
 * present send GARP packet to network peers with netif_notify_peers().
 */
static void netvsc_link_change(struct work_struct *w)
{
	struct net_device_context *ndev_ctx =
		container_of(w, struct net_device_context, dwork.work);
	struct hv_device *device_obj = ndev_ctx->device_ctx;
	struct net_device *net = hv_get_drvdata(device_obj);
	struct netvsc_device *net_device;
	struct rndis_device *rdev;
	struct netvsc_reconfig *event = NULL;
	bool notify = false, reschedule = false;
	unsigned long flags, next_reconfig, delay;

	if (!rtnl_trylock()) {
		schedule_delayed_work(&ndev_ctx->dwork, LINKCHANGE_INT);
		return;
	}

	net_device = rtnl_dereference(ndev_ctx->nvdev);
	if (!net_device)
		goto out_unlock;

	rdev = net_device->extension;

	next_reconfig = ndev_ctx->last_reconfig + LINKCHANGE_INT;
	if (time_is_after_jiffies(next_reconfig)) {
		/* link_watch only sends one notification with current state
		 * per second, avoid doing reconfig more frequently. Handle
		 * wrap around.
		 */
		delay = next_reconfig - jiffies;
		delay = delay < LINKCHANGE_INT ? delay : LINKCHANGE_INT;
		schedule_delayed_work(&ndev_ctx->dwork, delay);
		goto out_unlock;
	}
	ndev_ctx->last_reconfig = jiffies;

	spin_lock_irqsave(&ndev_ctx->lock, flags);
	if (!list_empty(&ndev_ctx->reconfig_events)) {
		event = list_first_entry(&ndev_ctx->reconfig_events,
					 struct netvsc_reconfig, list);
		list_del(&event->list);
		reschedule = !list_empty(&ndev_ctx->reconfig_events);
	}
	spin_unlock_irqrestore(&ndev_ctx->lock, flags);

	if (!event)
		goto out_unlock;

	switch (event->event) {
		/* Only the following events are possible due to the check in
		 * netvsc_linkstatus_callback()
		 */
	case RNDIS_STATUS_MEDIA_CONNECT:
		if (rdev->link_state) {
			rdev->link_state = false;
			if (!ndev_ctx->datapath)
				netif_carrier_on(net);
			netif_tx_wake_all_queues(net);
		} else {
			notify = true;
		}
		kfree(event);
		break;
	case RNDIS_STATUS_MEDIA_DISCONNECT:
		if (!rdev->link_state) {
			rdev->link_state = true;
			netif_carrier_off(net);
			netif_tx_stop_all_queues(net);
		}
		kfree(event);
		break;
	case RNDIS_STATUS_NETWORK_CHANGE:
		/* Only makes sense if carrier is present */
		if (!rdev->link_state) {
			rdev->link_state = true;
			netif_carrier_off(net);
			netif_tx_stop_all_queues(net);
			event->event = RNDIS_STATUS_MEDIA_CONNECT;
			spin_lock_irqsave(&ndev_ctx->lock, flags);
			list_add(&event->list, &ndev_ctx->reconfig_events);
			spin_unlock_irqrestore(&ndev_ctx->lock, flags);
			reschedule = true;
		}
		break;
	}

	rtnl_unlock();

	if (notify)
		netif_notify_peers(net);

	/* link_watch only sends one notification with current state per
	 * second, handle next reconfig event in 2 seconds.
	 */
	if (reschedule)
		schedule_delayed_work(&ndev_ctx->dwork, LINKCHANGE_INT);

	return;

out_unlock:
	rtnl_unlock();
}

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,2))
static void netvsc_notify_peers(struct work_struct *wrk)
{
	struct garp_wrk *gwrk;

	gwrk = container_of(wrk, struct garp_wrk, dwrk);

	netif_notify_peers(gwrk->netdev);

	atomic_dec(&gwrk->net_device_ctx->vf_use_cnt);
}
#endif

static struct net_device *get_netvsc_bymac(const u8 *mac)
{
	struct net_device *dev;

	ASSERT_RTNL();

	for_each_netdev(&init_net, dev) {
		if (dev->netdev_ops != &device_ops)
			continue;	/* not a netvsc device */

		/* deviation from upstream - we are using dev_addr, not perm_addr */
		if (ether_addr_equal(mac, dev->dev_addr))
			return dev;
	}

	return NULL;
}

static struct net_device *get_netvsc_byref(const struct net_device *vf_netdev)
{
	struct net_device *dev;

	ASSERT_RTNL();

	for_each_netdev(&init_net, dev) {
		struct net_device_context *net_device_ctx;

		if (dev->netdev_ops != &device_ops)
			continue;	/* not a netvsc device */

		net_device_ctx = netdev_priv(dev);
		if (!rtnl_dereference(net_device_ctx->nvdev))
			continue;	/* device is removed */

		if (net_device_ctx->vf_netdev == vf_netdev)
			return dev;	/* a match */
	}

	return NULL;
}

static int netvsc_register_vf(struct net_device *vf_netdev)
{
	struct net_device *ndev;
	struct net_device_context *net_device_ctx;
	struct netvsc_device *netvsc_dev;

	if (vf_netdev->addr_len != ETH_ALEN)
		return NOTIFY_DONE;

	/*
	 * We will use the MAC address to locate the synthetic interface to
	 * associate with the VF interface. If we don't find a matching
	 * synthetic interface, move on.
	 */
	/* deviation from upstream - we are using dev_addr rather than perm_addr */
	ndev = get_netvsc_bymac(vf_netdev->dev_addr);
	if (!ndev)
		return NOTIFY_DONE;

	net_device_ctx = netdev_priv(ndev);
	netvsc_dev = net_device_ctx->nvdev;
	if (!netvsc_dev || net_device_ctx->vf_netdev)
		return NOTIFY_DONE;

	netdev_info(ndev, "VF registering: %s\n", vf_netdev->name);
	/*
	 * Take a reference on the module.
	 */
	try_module_get(THIS_MODULE);

	dev_hold(vf_netdev);
	net_device_ctx->vf_netdev = vf_netdev;
	return NOTIFY_OK;
}

static void netvsc_inject_enable(struct net_device_context *net_device_ctx)
{
	net_device_ctx->vf_inject = true;
}

static void netvsc_inject_disable(struct net_device_context *net_device_ctx)
{
	net_device_ctx->vf_inject = false;

	/* Wait for currently active users to drain out. */
	while (atomic_read(&net_device_ctx->vf_use_cnt) != 0)
		udelay(50);
}

static int netvsc_vf_up(struct net_device *vf_netdev)
{
	struct net_device *ndev;
	struct netvsc_device *netvsc_dev;
	struct net_device_context *net_device_ctx;

	ndev = get_netvsc_byref(vf_netdev);
	if (!ndev)
		return NOTIFY_DONE;

	net_device_ctx = netdev_priv(ndev);
	netvsc_dev = net_device_ctx->nvdev;

	if (!net_device_ctx->synthetic_data_path)
		return NOTIFY_DONE;

	netdev_info(ndev, "VF up: %s\n", vf_netdev->name);
	netvsc_inject_enable(net_device_ctx);

	/*
	 * Open the device before switching data path.
	 */
	rndis_filter_open(netvsc_dev);

	/*
	 * notify the host to switch the data path.
	 */
	netvsc_switch_datapath(ndev, true);
	net_device_ctx->synthetic_data_path = false;
	netdev_info(ndev, "Data path switched to VF: %s\n", vf_netdev->name);

	netif_carrier_off(ndev);

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,2))
	/*
	 * Now notify peers. We are scheduling work to
	 * notify peers; take a reference to prevent
	 * the VF interface from vanishing.
	 */
	atomic_inc(&net_device_ctx->vf_use_cnt);
	net_device_ctx->gwrk.netdev = vf_netdev;
	net_device_ctx->gwrk.net_device_ctx = net_device_ctx;
	schedule_work(&net_device_ctx->gwrk.dwrk);
#else
	/* Now notify peers through VF device. */
	call_netdevice_notifiers(NETDEV_NOTIFY_PEERS, vf_netdev);
#endif
	return NOTIFY_OK;
}

static int netvsc_vf_down(struct net_device *vf_netdev, bool rndis_close)
{
	struct net_device *ndev;
	struct netvsc_device *netvsc_dev;
	struct net_device_context *net_device_ctx;

	ndev = get_netvsc_byref(vf_netdev);
	if (!ndev)
		return NOTIFY_DONE;

	net_device_ctx = netdev_priv(ndev);
	netvsc_dev = net_device_ctx->nvdev;

	if (net_device_ctx->synthetic_data_path)
		return NOTIFY_DONE;

	netdev_info(ndev, "VF down: %s\n", vf_netdev->name);
	netvsc_inject_disable(net_device_ctx);
	netvsc_switch_datapath(ndev, false);
	netdev_info(ndev, "Data path switched from VF: %s\n", vf_netdev->name);
	net_device_ctx->synthetic_data_path = true;
	if (rndis_close)
		rndis_filter_close(netvsc_dev);
	netif_carrier_on(ndev);

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,2))
	/*
	 * Notify peers.
	 */
	atomic_inc(&net_device_ctx->vf_use_cnt);
	net_device_ctx->gwrk.netdev = ndev;
	net_device_ctx->gwrk.net_device_ctx = net_device_ctx;
	schedule_work(&net_device_ctx->gwrk.dwrk);
#else
	/* Now notify peers through netvsc device. */
	call_netdevice_notifiers(NETDEV_NOTIFY_PEERS, ndev);
#endif

	return NOTIFY_OK;
}

static int netvsc_unregister_vf(struct net_device *vf_netdev)
{
	struct net_device *ndev;
	struct net_device_context *net_device_ctx;

	ndev = get_netvsc_byref(vf_netdev);
	if (!ndev)
		return NOTIFY_DONE;

	net_device_ctx = netdev_priv(ndev);

	netvsc_vf_down(vf_netdev, false);

	netdev_info(ndev, "VF unregistering: %s\n", vf_netdev->name);
	netvsc_inject_disable(net_device_ctx);
	net_device_ctx->vf_netdev = NULL;
	dev_put(vf_netdev);
	module_put(THIS_MODULE);
	return NOTIFY_OK;
}

static int netvsc_probe(struct hv_device *dev,
			const struct hv_vmbus_device_id *dev_id)
{
	struct net_device *net = NULL;
	struct net_device_context *net_device_ctx;
	struct netvsc_device_info device_info;
	struct netvsc_device *nvdev;
	int ret;

	net = alloc_etherdev_mq(sizeof(struct net_device_context),
				VRSS_CHANNEL_MAX);
	if (!net)
		return -ENOMEM;

	netif_carrier_off(net);

	netvsc_init_settings(net);

	net_device_ctx = netdev_priv(net);
	net_device_ctx->device_ctx = dev;
	net_device_ctx->msg_enable = netif_msg_init(debug, default_msg);
	if (netif_msg_probe(net_device_ctx))
		netdev_dbg(net, "netvsc msg_enable: %d\n",
			net_device_ctx->msg_enable);

	hv_set_drvdata(dev, net);

	net_device_ctx->synthetic_data_path = true;

	INIT_DELAYED_WORK(&net_device_ctx->dwork, netvsc_link_change);
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,2))
	INIT_WORK(&net_device_ctx->gwrk.dwrk, netvsc_notify_peers);
#endif
	spin_lock_init(&net_device_ctx->lock);
	INIT_LIST_HEAD(&net_device_ctx->reconfig_events);

	atomic_set(&net_device_ctx->vf_use_cnt, 0);
	net_device_ctx->vf_netdev = NULL;
	net_device_ctx->vf_inject = false;

	net->netdev_ops = &device_ops;
	net->ethtool_ops = &ethtool_ops;
	SET_NETDEV_DEV(net, &dev->device);

	netif_set_real_num_tx_queues(net, 1);
#ifdef NOTYET
	netif_set_real_num_rx_queues(net, 1);
#endif

	/* Notify the netvsc driver of the new device */
	memset(&device_info, 0, sizeof(device_info));
	device_info.ring_size = ring_size;
	device_info.num_chn = VRSS_CHANNEL_DEFAULT;

	nvdev = rndis_filter_device_add(dev, &device_info);
	if (IS_ERR(nvdev)) {
		ret = PTR_ERR(nvdev);
		netdev_err(net, "unable to add netvsc device (ret %d)\n", ret);
		free_netdev(net);
		hv_set_drvdata(dev, NULL);
		return ret;
	}
	memcpy(net->dev_addr, device_info.mac_adr, ETH_ALEN);

#ifdef NOTYET
	/* hw_features computed in rndis_filter_device_add */
	net->features = net->hw_features |
		NETIF_F_HIGHDMA | NETIF_F_SG |
		NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX;
#endif
	// Need to explicitly set NETIF_F_HW_VLAN_TX support on RH6.X kernels.
	net->features |= NETIF_F_HIGHDMA | NETIF_F_SG |
	NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_TX;

	net->vlan_features = net->features;

	netdev_lockdep_set_classes(net);

	dev_info(&dev->device, "real num tx,rx queues:%u, %u\n",
		 net->real_num_tx_queues, nvdev->num_chn);

	ret = register_netdev(net);
	if (ret != 0) {
		pr_err("Unable to register netdev.\n");
		rndis_filter_device_remove(dev, nvdev);
		free_netdev(net);
	}

	return ret;
}

static int netvsc_remove(struct hv_device *dev)
{
	struct net_device *net;
	struct net_device_context *ndev_ctx;

	net = hv_get_drvdata(dev);

	if (net == NULL) {
		dev_err(&dev->device, "No net device to remove\n");
		return 0;
	}

	ndev_ctx = netdev_priv(net);

	netif_device_detach(net);

	cancel_delayed_work_sync(&ndev_ctx->dwork);

	unregister_netdev(net);

	/*
	 * Call to the vsc driver to let it know that the device is being
	 * removed. Also blocks mtu and channel changes.
	 */
	rtnl_lock();
	rndis_filter_device_remove(dev,
				   rtnl_dereference(ndev_ctx->nvdev));
	rtnl_unlock();

	hv_set_drvdata(dev, NULL);

	free_netdev(net);	
	return 0;
}

static const struct hv_vmbus_device_id id_table[] = {
	/* Network guid */
	{ HV_NIC_GUID, },
	{ },
};

MODULE_DEVICE_TABLE(vmbus, id_table);

/* The one and only one */
static struct  hv_driver netvsc_drv = {
	.name = KBUILD_MODNAME,
	.id_table = id_table,
	.probe = netvsc_probe,
	.remove = netvsc_remove,
};

/*
 * On Hyper-V, every VF interface is matched with a corresponding
 * synthetic interface. The synthetic interface is presented first
 * to the guest. When the corresponding VF instance is registered,
 * we will take care of switching the data path.
 */
static int netvsc_netdev_event(struct notifier_block *this,
			       unsigned long event, void *ptr)
{
#if (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,10))
	/* Not in RHEL 6.8 kernel - check again when 6.9 releases - NHM */
	struct net_device *event_dev = netdev_notifier_info_to_dev(ptr);
#else
	struct net_device *event_dev = ptr;
#endif
	/* Skip our own events */
	if (event_dev->netdev_ops == &device_ops)
		return NOTIFY_DONE;

	/* Avoid non-Ethernet type devices */
	if (event_dev->type != ARPHRD_ETHER)
		return NOTIFY_DONE;

	/* Avoid Vlan dev with same MAC registering as VF */
	if (is_vlan_dev(event_dev))
		return NOTIFY_DONE;

	/* Avoid Bonding master dev with same MAC registering as VF */
	if ((event_dev->priv_flags & IFF_BONDING) &&
	    (event_dev->flags & IFF_MASTER))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_REGISTER:
		return netvsc_register_vf(event_dev);
	case NETDEV_UNREGISTER:
		return netvsc_unregister_vf(event_dev);
	case NETDEV_UP:
		return netvsc_vf_up(event_dev);
	case NETDEV_DOWN:
		return netvsc_vf_down(event_dev, true);
	default:
		return NOTIFY_DONE;
	}
}

static struct notifier_block netvsc_netdev_notifier = {
	.notifier_call = netvsc_netdev_event,
};


static void __exit netvsc_drv_exit(void)
{
	unregister_netdevice_notifier(&netvsc_netdev_notifier);
	vmbus_driver_unregister(&netvsc_drv);
}

static int __init netvsc_drv_init(void)
{
	int ret;

	if (ring_size < RING_SIZE_MIN) {
		ring_size = RING_SIZE_MIN;
		pr_info("Increased ring_size to %d (min allowed)\n",
			ring_size);
	}
	ret = vmbus_driver_register(&netvsc_drv);

	if (ret)
		return ret;

	register_netdevice_notifier(&netvsc_netdev_notifier);
	return 0;
}

MODULE_LICENSE("GPL");
MODULE_VERSION(HV_DRV_VERSION);
MODULE_DESCRIPTION("Microsoft Hyper-V network driver");
MODULE_ALIAS("vmbus:635161f83edfc546913ff2d2f965ed0e");

module_init(netvsc_drv_init);
module_exit(netvsc_drv_exit);
