/*   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2 of the License
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   Copyright (C) 2014-2016 Sean Wang <sean.wang@mediatek.com>
 *   Copyright (C) 2016-2017 John Crispin <blogic@openwrt.org>
 */

#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ppp_defs.h>
#include <linux/version.h>

#include <net/arp.h>
#include <net/neighbour.h>
#include <net/netfilter/nf_conntrack_helper.h>
//#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_hnat.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>

#include "nf_hnat_mtk.h"
#include "hnat.h"

#include "../mtk_eth_soc.h"
//#include "../mtk_eth_reset.h"

#define DEBUG_TRACE 0

static struct ipv6hdr mape_l2w_v6h;
static struct ipv6hdr mape_w2l_v6h;
static inline size_t get_wifi_hook_index_from_dev(const struct net_device *dev)
{
	size_t i;

	for (i = 0; i < MAX_IF_NUM; ++i) {
		if (hnat_priv->wifi_hook_if[i] == dev)
			return i + 1;
	}

	return 0;
}

static inline size_t find_extif_from_devname(const char *name)
{
	size_t i;
	struct extdev_entry *ext_entry;

	for (i = 0; i < MAX_EXT_DEVS &&
	     (ext_entry = hnat_priv->ext_if[i]); ++i) {
		if (!strcmp(ext_entry->name, name))
			return i + 1;
	}

	return 0;
}

static inline size_t get_index_from_dev(const struct net_device *dev)
{
	size_t i;
	struct extdev_entry *ext_entry;

	for (i = 0; i < MAX_EXT_DEVS &&
	     (ext_entry = hnat_priv->ext_if[i]); ++i) {
		if (ext_entry->dev == dev)
			//return dev->ifindex;
			return i + 1;
	}

	return 0;
}

static inline struct net_device *get_dev_from_index(int index)
{
	size_t i;
	struct extdev_entry *ext_entry;
	struct net_device *dev;

	for (i = 0; i < MAX_EXT_DEVS &&
	     (ext_entry = hnat_priv->ext_if[i]); ++i) {
		if ((dev = ext_entry->dev) != 0 &&
		    dev->ifindex == index)
			return dev;
	}

	return NULL;
}

static inline struct net_device *get_wandev_from_index(int index)
{
	struct net_device *dev;

	if ((dev = hnat_priv->g_wandev) != 0) {
	} else if ((dev = dev_get_by_name(&init_net, hnat_priv->wan)) != 0)
		hnat_priv->g_wandev = dev;
	else
		return NULL;

	if (dev->ifindex == index)
		return dev;

	return NULL;
}

static inline size_t extif_set_dev(struct net_device *dev)
{
	size_t i;
	struct extdev_entry *ext_entry;

	for (i = 0; i < MAX_EXT_DEVS &&
	     (ext_entry = hnat_priv->ext_if[i]); ++i) {
		if (!strcmp(ext_entry->name, dev->name) && ext_entry->dev == 0) {
			dev_hold(dev);
			ext_entry->dev = dev;
			pr_info("%s(%s)\n", __func__, dev->name);
			return i + 1;
		}
	}

	return 0;
}

static inline size_t extif_put_dev(struct net_device *dev)
{
	size_t i;
	struct extdev_entry *ext_entry;

	for (i = 0; i < MAX_EXT_DEVS &&
	     (ext_entry = hnat_priv->ext_if[i]); ++i) {
		if (ext_entry->dev == dev) {
			ext_entry->dev = NULL;
			dev_put(dev);
			pr_info("%s(%s)\n", __func__, dev->name);
			return i + 1;
		}
	}

	return 0;
}

size_t ext_if_add(struct extdev_entry *ext_entry)
{
	size_t i;

	for (i = 0; i < MAX_EXT_DEVS; ++i) {
		if (!hnat_priv->ext_if[i]) {
			hnat_priv->ext_if[i] = ext_entry;
			return i + 1;
		}
	}

	return 0;
}

size_t ext_if_del(struct extdev_entry *ext_entry)
{
	size_t i, j;

	for (i = 0; i < MAX_EXT_DEVS; ++i) {
		if (hnat_priv->ext_if[i] == ext_entry) {
			for (j = i; ++j < MAX_EXT_DEVS && hnat_priv->ext_if[j];)
				hnat_priv->ext_if[j - 1] = hnat_priv->ext_if[j];
			hnat_priv->ext_if[j - 1] = NULL;
			return i + 1;
		}
	}

	return 0;
}

void foe_clear_all_bind_entries(void)
{
	int i, hash_index;
	struct foe_entry *entry;

	for (i = 0; i < CFG_PPE_NUM; i++) {
		cr_set_field(hnat_priv->ppe_base[i] + PPE_TB_CFG,
			     SMA, SMA_ONLY_FWD_CPU);

		for (hash_index = 0; hash_index < hnat_priv->foe_etry_num; hash_index++) {
			entry = hnat_priv->foe_table_cpu[i] + hash_index;
			if (entry->bfib1.state == BIND) {
				entry->udib1.state = INVALID;
				entry->udib1.time_stamp =
					readl((hnat_priv->fe_base + 0x0010)) & 0xFF;
			}
		}
	}

	/* clear HWNAT cache */
	hnat_cache_ebl(1);

	mod_timer(&hnat_priv->hnat_sma_build_entry_timer, jiffies + 3 * HZ);
}

static void gmac_ppe_fwd_enable(struct net_device *dev)
{
	if (IS_LAN(dev) || IS_GMAC1_MODE)
		set_gmac_ppe_fwd(NR_GMAC1_PORT, 1);
	else if (IS_WAN(dev))
		set_gmac_ppe_fwd(NR_GMAC2_PORT, 1);
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	else if (IS_LAN2(dev))
		set_gmac_ppe_fwd(NR_GMAC3_PORT, 1);
#endif
}

int nf_hnat_netdevice_event(struct notifier_block *unused, unsigned long event,
			    void *ptr)
{
	struct net_device *dev;

	dev = netdev_notifier_info_to_dev(ptr);

	switch (event) {
	case NETDEV_UP:
		if (!hnat_priv->guest_en && dev->name) {
			if (!strcmp(dev->name, "ra1") || !strcmp(dev->name, "rai1") || !strcmp(dev->name, "rax1"))
				break;
		}

		gmac_ppe_fwd_enable(dev);

		extif_set_dev(dev);

		break;
	case NETDEV_GOING_DOWN:
		if (!get_wifi_hook_index_from_dev(dev))
			extif_put_dev(dev);

		if (!IS_LAN_GRP(dev) && !IS_WAN(dev) &&
		    !find_extif_from_devname(dev->name) &&
		    //!dev->netdev_ops->ndo_flow_offload_check)
		    !dev->netdev_ops->ndo_hnat_check)
			break;

		foe_clear_all_bind_entries();

		break;
	case NETDEV_UNREGISTER:
		if (hnat_priv->g_ppdev == dev) {
			hnat_priv->g_ppdev = NULL;
			dev_put(dev);
		}
		if (hnat_priv->g_wandev == dev) {
			hnat_priv->g_wandev = NULL;
			dev_put(dev);
		}

		break;
	case NETDEV_REGISTER:
		if (!hnat_priv->g_ppdev && IS_PPD(dev))
			hnat_priv->g_ppdev = dev_get_by_name(&init_net, hnat_priv->ppd);
		if (!hnat_priv->g_wandev && IS_WAN(dev))
			hnat_priv->g_wandev = dev_get_by_name(&init_net, hnat_priv->wan);

		break;
	/*TODO:case MTK_FE_RESET_NAT_DONE:
		pr_info("[%s] HNAT driver starts to do warm init !\n", __func__);
		hnat_warm_init();
		break;*/
	default:
		break;
	}

	return NOTIFY_DONE;
}

void foe_clear_entry(struct neighbour *neigh)
{
	u32 *daddr = (u32 *)neigh->primary_key;
	unsigned char h_dest[ETH_ALEN];
	struct foe_entry *entry;
	int i, hash_index;
	u32 dip;

	dip = (u32)(*daddr);

	for (i = 0; i < CFG_PPE_NUM; i++) {
		if (!hnat_priv->foe_table_cpu[i])
			continue;

		for (hash_index = 0; hash_index < hnat_priv->foe_etry_num; hash_index++) {
			entry = hnat_priv->foe_table_cpu[i] + hash_index;
			if (entry->bfib1.state == BIND &&
			    entry->ipv4_hnapt.new_dip == ntohl(dip) &&
			    //IS_IPV4_HNAPT(entry)) {
			    IS_IPV4_GRP(entry)) {
				*((u32 *)h_dest) = swab32(entry->ipv4_hnapt.dmac_hi);
				*((u16 *)&h_dest[4]) =
					swab16(entry->ipv4_hnapt.dmac_lo);
				//if (strncmp(h_dest, neigh->ha, ETH_ALEN) != 0) {
				if (!ether_addr_equal(h_dest, neigh->ha)) {
					cr_set_field(hnat_priv->ppe_base[i] + PPE_TB_CFG,
						     SMA, SMA_ONLY_FWD_CPU);

					entry->udib1.state = INVALID;
					entry->udib1.time_stamp =
						readl((hnat_priv->fe_base + 0x0010)) & 0xFF;

					/* clear HWNAT cache */
					hnat_cache_ebl(1);

					mod_timer(&hnat_priv->hnat_sma_build_entry_timer,
						  jiffies + 3 * HZ);

					if (debug_level >= 7) {
						pr_info("%s: state=%d\n", __func__,
							neigh->nud_state);
						pr_info("Delete old entry: dip =%pI4\n", &dip);
						pr_info("Old mac= %pM\n", h_dest);
						pr_info("New mac= %pM\n", neigh->ha);
					}
				}
			}
		}
	}
}

int nf_hnat_netevent_handler(struct notifier_block *unused, unsigned long event,
			     void *ptr)
{
	struct net_device *dev = NULL;
	struct neighbour *neigh = NULL;

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		neigh = ptr;
		dev = neigh->dev;
		if (dev)
			foe_clear_entry(neigh);
		break;
	}

	return NOTIFY_DONE;
}

int mape_add_ipv6_hdr(struct sk_buff *skb, struct ipv6hdr *mape_ip6h)
{
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;

	/* point to L2 */
	/*if (skb_headroom(skb) < sizeof(*ip6h) || skb_shared(skb) ||
	    (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
		return -2;
	}*/

	eth = (struct ethhdr *)__skb_push(skb, sizeof(*ip6h));
	ip6h = (struct ipv6hdr *)((u8 *)eth + ETH_HLEN);
	iph = (struct iphdr *)((u8 *)eth + ETH_HLEN + sizeof(*ip6h));

	memcpy(eth, (u8 *)eth + sizeof(*ip6h), ETH_HLEN);
	memcpy(ip6h, mape_ip6h, sizeof(*ip6h));

	ip6h->payload_len = iph->tot_len; /* maybe different with ipv4 */
	eth->h_proto = htons(ETH_P_IPV6);
	skb->protocol = htons(ETH_P_IPV6);
	/*skb_set_transport_header(skb, sizeof(*ip6h) + iph->ihl * 4);*/
	//skb_set_network_header(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	return 0;
}

static __be16 remove_vlan_tag(struct sk_buff *skb)
{
	struct vlan_hdr *vhdr = (struct vlan_hdr *)(skb->data + ETH_HLEN);
	__be16 vlan_tci = vhdr->h_vlan_TCI;

	/*if (skb_cloned(skb) || skb_shared(skb)) {
		struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);

		//Free our shared copy
		if (likely(nskb))
			consume_skb(skb);
		else
			kfree_skb(skb);
		skb = nskb;
		if (!skb)
			return -2;
	}*/

	/* remove VLAN tag */
	vlan_set_encap_proto(skb, vhdr);
	skb->mac_header += VLAN_HLEN;
	memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);
	__skb_pull(skb, VLAN_HLEN);	/* pointer to layer2 header */
	return vlan_tci;
}

static int is_ppe_support_type(struct sk_buff *skb);
int do_hnat_ext_to_ge(struct sk_buff *skb, __u16 vlan_tci,
			       const char *func)
{
	struct net_device *dev;

	if (!is_ppe_support_type(skb))
		return -4;

	if ((dev = hnat_priv->g_ppdev) != 0) {
	} else if ((dev = dev_get_by_name(&init_net, hnat_priv->ppd)) != 0)
		hnat_priv->g_ppdev = dev;
	else
		return -2;

	if ((dev->flags & IFF_UP) == 0)
		return -3;

	__skb_push(skb, ETH_HLEN);
	skb_set_network_header(skb, ETH_HLEN);

	/*if (skb_vlan_tag_get_id(skb)) {
		skb = vlan_insert_tag(skb, skb->vlan_proto, skb->vlan_tci);
		if (!skb)
			return 0;
	}*/
	// FIXME: skb->protocol
	if (skb_vlan_tag_present(skb) &&
	    __vlan_insert_tag(skb, skb->vlan_proto, skb_vlan_tag_get(skb))) {
		trace_printk("%s: called from %s fail\n", __func__, func);
		dev_kfree_skb_any(skb);
		return 0;
	}

	/*set where we come from*/
	/*skb->vlan_proto = htons(ETH_P_8021Q);
	skb->vlan_tci =
		(VLAN_CFI_MASK | (in->ifindex & VLAN_VID_MASK));*/
	__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tci & VLAN_VID_MASK);
#if DEBUG_TRACE
	trace_printk(
		"%s: vlan_prot=0x%x, vlan_tci=%x, vlan_tci=%x, name=%s\n",
		__func__, ntohs(skb->vlan_proto), skb->vlan_tci,
		vlan_tci, skb->dev->name);
#endif

	skb->dev = dev;
#ifdef CONFIG_SHORTCUT_FE
	skb->fast_forwarded = 1;
#endif
	set_to_ppe(skb);
	dev_queue_xmit(skb);
#if DEBUG_TRACE
	trace_printk("%s: called from %s successfully\n", __func__, func);
#endif
	return 0;
}

int do_hnat_ext_to_ge2(struct sk_buff *skb, __u16 vlan_tci,
			       const char *func)
{
	/*set where we to go*/
	struct net_device *dev;
	//struct foe_entry *entry;

#if DEBUG_TRACE
	trace_printk("%s: vlan_prot=0x%x, vlan_tci=%x\n", __func__,
		     ntohs(skb->vlan_proto), vlan_tci);
#endif

	vlan_tci &= VLAN_VID_MASK;
	if ((dev = get_wandev_from_index(vlan_tci)) == 0) {
		if ((dev = get_dev_from_index(vlan_tci)) == 0) {
			trace_printk("%s: called from %s fail\n", __func__, func);
			return -2;
		}
		set_from_extge(skb);
		if (IS_BOND_MODE &&
#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
		    skb_hnat_entry(skb) != 0x7fff)
#else
		    skb_hnat_entry(skb) != 0x3fff)
#endif
				skb_set_hash(skb, skb_hnat_entry(skb) >> 1, PKT_HASH_TYPE_L4);
	} else {
		/* MapE WAN --> LAN/WLAN PingPong. */
		if (!mape_toggle ||
		    mape_add_ipv6_hdr(skb, &mape_w2l_v6h)) {
			trace_printk("%s: called from %s fail[MapE]\n", __func__,
				     func);
			return -3;
		}
		set_from_mape(skb);
		//entry = &hnat_priv->foe_table_cpu[skb_hnat_ppe(skb)][skb_hnat_entry(skb)];
		//entry->bfib1.pkt_type = IPV4_HNAPT;
	}

	skb->pkt_type = PACKET_HOST;
	skb->gro_skip = 0;
	skb->protocol = eth_type_trans(skb, dev);
	/*skb->dev = dev;
	__skb_pull(skb, ETH_HLEN);*/
	netif_rx(skb);
#if DEBUG_TRACE
	trace_printk("%s: called from %s successfully\n", __func__,
		     func);
#endif
	return 0;
}

int do_hnat_ge_to_ext(struct sk_buff *skb, struct foe_entry *entry, const char *func)
{
	/*set where we to go*/
	__u16 index;
	struct net_device *dev;

	if (IS_IPV4_GRP(entry))
		index = entry->ipv4_hnapt.act_dp;
	else
		index = entry->ipv6_5t_route.act_dp;

	if ((--index) < MAX_EXT_DEVS) {
		struct extdev_entry *ext_entry = hnat_priv->ext_if[index];
		if ((dev = ext_entry ? ext_entry->dev : 0) == 0) {
			trace_printk("%s: called from %s fail, index=%x\n", __func__,
				     func, index);
			goto drop;
		}
	} else {
		/* Add ipv6 header mape for lan/wlan -->wan */
		if (!mape_toggle || (dev = hnat_priv->g_wandev) == 0 ||
		    mape_add_ipv6_hdr(skb, &mape_l2w_v6h)) {
			trace_printk("%s: called from %s fail[MapE]\n", __func__,
				     func);
drop:
			/*if external devices is down, invalidate related ppe entry*/
			if (entry_hnat_is_bound(entry)) {
				entry->udib1.state = INVALID;
				entry->udib1.time_stamp =
					readl((hnat_priv->fe_base + 0x0010)) & 0xFF;
				if (IS_IPV4_GRP(entry))
					entry->ipv4_hnapt.act_dp = 0;
				else
					entry->ipv6_5t_route.act_dp = 0;

				/* clear HWNAT cache */
				hnat_cache_ebl(1);
			}
			return -2;
		}
	}

	skb->dev = dev;
#ifdef CONFIG_SHORTCUT_FE
	skb->fast_forwarded = 1;
#endif
	skb_set_network_header(skb, ETH_HLEN);
	dev_queue_xmit(skb);
#if DEBUG_TRACE
	trace_printk("%s: called from %s successfully\n", __func__,
		     func);
#endif
	return 0;
}

static inline void ppe_fill_flow_lbl(struct foe_entry *entry, struct ipv6hdr *ip6h)
{
	entry->ipv4_dslite.flow_lbl[0] = ip6h->flow_lbl[2];
	entry->ipv4_dslite.flow_lbl[1] = ip6h->flow_lbl[1];
	entry->ipv4_dslite.flow_lbl[2] = ip6h->flow_lbl[0];
}

int do_hnat_mape_w2l_fast(struct sk_buff *skb, __u16 vlan_tci,
				   const char *func)
{
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	struct net_device *dev;

	/* WAN -> LAN/WLAN MapE. */
	switch (skb->protocol) {
	case htons(ETH_P_IPV6):
		ip6h = (struct ipv6hdr *)skb->data;
		switch (ip6h->nexthdr) {
		case NEXTHDR_IPIP:
			iph = (struct iphdr *)((u8 *)ip6h + sizeof(*ip6h));
			switch (iph->protocol) {
			case IPPROTO_UDP:
			case IPPROTO_TCP:
				break;
			default:
				return -6;
			}
			break;
		default:
			return -5;
		}
		break;
	default:
		return -4;
	}

	if ((dev = hnat_priv->g_ppdev) != 0) {
	} else if ((dev = dev_get_by_name(&init_net, hnat_priv->ppd)) != 0)
		hnat_priv->g_ppdev = dev;
	else
		return -2;

	if ((dev->flags & IFF_UP) == 0)
		return -3;

	/* Remove ipv6 header. */
	mape_w2l_v6h = *ip6h;
	eth = (struct ethhdr *)__skb_pull(skb, sizeof(*ip6h) - ETH_HLEN);
	memcpy(eth, (u8 *)eth - sizeof(*ip6h), ETH_HLEN);
	eth->h_proto = htons(ETH_P_IP);
	skb->protocol = htons(ETH_P_IP);
	/*skb_set_transport_header(skb, ETH_HLEN + iph->ihl * 4);*/
	skb_set_network_header(skb, ETH_HLEN);
	skb_reset_mac_header(skb);

	if (skb_vlan_tag_present(skb) &&
	    __vlan_insert_tag(skb, skb->vlan_proto, skb_vlan_tag_get(skb))) {
		trace_printk("%s: called from %s fail\n", __func__, func);
		dev_kfree_skb_any(skb);
		return 0;
	}

	/*skb->vlan_proto = htons(ETH_P_8021Q);
	skb->vlan_tci =
	(VLAN_CFI_MASK | (in->ifindex & VLAN_VID_MASK));*/
	__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tci & VLAN_VID_MASK);

	skb->dev = dev;
#ifdef CONFIG_SHORTCUT_FE
	skb->fast_forwarded = 1;
#endif
	set_to_ppe(skb);
	dev_queue_xmit(skb);
	return 0;
}

void mtk_464xlat_pre_process(struct sk_buff *skb)
{
	struct foe_entry *foe;

	if (skb_hnat_entry(skb) >= hnat_priv->foe_etry_num ||
	    skb_hnat_ppe(skb) >= CFG_PPE_NUM)
		return;

	foe = &hnat_priv->foe_table_cpu[skb_hnat_ppe(skb)][skb_hnat_entry(skb)];
	if (foe->bfib1.state != BIND &&
	    skb_hnat_reason(skb) == HIT_UNBIND_RATE_REACH)
		memcpy(&headroom[skb_hnat_entry(skb)], skb->head,
		       //sizeof(struct hnat_desc));
		       FOE_INFO_LEN);

	if (foe->bfib1.state == BIND)
		memset(&headroom[skb_hnat_entry(skb)], 0,
		       //sizeof(struct hnat_desc));
		       FOE_INFO_LEN);
}

static int is_ppe_support_type(struct sk_buff *skb)
{
	/*if (!is_magic_tag_valid(skb) || !IS_SPACE_AVAILABLE_HEAD(skb) ||
	    is_broadcast_ether_addr(eth_hdr(skb)->h_dest))*/
	/*if (!is_magic_tag_valid(skb) || !IS_SPACE_AVAILABLE_HEAD(skb) ||
	    is_multicast_ether_addr(eth_hdr(skb)->h_dest))*/

	switch (skb->protocol) {
	case htons(ETH_P_8021Q):
	case htons(ETH_P_PPP_SES):
		return 1;
	case htons(ETH_P_IP):
		/* do not accelerate non tcp/udp traffic */
		switch (((struct iphdr *)skb->data)->protocol) {
		case IPPROTO_UDP:
		case IPPROTO_TCP:
		case IPPROTO_IPV6:
			return 1;
		}
		break;
	case htons(ETH_P_IPV6):
		switch (((struct ipv6hdr *)skb->data)->nexthdr) {
		case NEXTHDR_UDP:
		case NEXTHDR_TCP:
			return 1;
		case NEXTHDR_IPIP:
			switch (((struct iphdr *)(skb->data + sizeof(struct ipv6hdr)))->protocol) {
			case IPPROTO_UDP:
			case IPPROTO_TCP:
				return 1;
			}
			break;
		}
		break;
	}

	return 0;
}

static u16 ppe_get_chkbase(struct iphdr *iph)
{
	u16 org_chksum = ntohs(iph->check);
	u16 org_tot_len = ntohs(iph->tot_len);
	u16 org_id = ntohs(iph->id);
	u16 chksum_tmp, tot_len_tmp, id_tmp;
	u32 tmp = 0;
	u16 chksum_base = 0;

	chksum_tmp = ~(org_chksum);
	tot_len_tmp = ~(org_tot_len);
	id_tmp = ~(org_id);
	tmp = chksum_tmp + tot_len_tmp + id_tmp;
	tmp = ((tmp >> 16) & 0x7) + (tmp & 0xFFFF);
	tmp = ((tmp >> 16) & 0x7) + (tmp & 0xFFFF);
	chksum_base = tmp & 0xFFFF;

	return chksum_base;
}

enum ppe_l2_ecode {
	_EMCAST = 2,
	_EPKTTYPE,
	_EPKTTYPECHECK,
	_EDPORT,
	_EPPPOE,
	_EPPPPROTO,
};

int ppe_copy_foe_entry(struct foe_entry *dst, const struct foe_entry *src, bool full) {
	u8 pkt_type = src->udib1.pkt_type;
	switch (pkt_type) {
	case IPV4_HNAPT:
	case IPV4_HNAT:
		/* IPV4_HNAPT->IPV4_MAP_E,IPV4_DSLITE,IPV4_HNAPT */
		/* IPV4_HNAT->IPV4_HNAT */
		if (full) {
			memcpy(dst, src, sizeof(struct foe_entry));
		} else {
			size_t offset = offsetof(struct hnat_ipv4_hnapt, info_blk2);
			memcpy(dst, src, offset);
			memset(&dst->ipv4_hnapt.info_blk2, 0x00,
				sizeof(struct foe_entry) - offset);
		}
		break;
#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
	case IPV4_MAP_E:
#endif
	case IPV4_DSLITE:
	case IPV6_6RD:
	case IPV6_5T_ROUTE:
	case IPV6_3T_ROUTE:
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	case IPV6_HNAPT:
	case IPV6_HNAT:
#endif
		/* IPV4_MAP_E->IPV4_MAP_E */
		/* IPV4_DSLITE->IPV4_DSLITE */
		/* IPV6_6RD->IPV6_6RD */
		/* IPV6_5T_ROUTE->IPV6_6RD,IPV6_5T_ROUTE,IPV6_HNAPT,IPV6_HNAT */
		/* IPV6_3T_ROUTE->IPV6_3T_ROUTE,IPV6_HNAT */
		/* IPV6_1T_ROUTE->IPV6_1T_ROUTE */
		if (full) {
			memcpy(dst, src, sizeof(struct foe_entry));
		} else {
			size_t offset = offsetof(struct hnat_ipv4_dslite, flow_lbl[0]);
			memcpy(dst, src, offset);
			memset(&dst->ipv4_dslite.flow_lbl[0], 0x00,
				sizeof(struct foe_entry) - offset);
		}
		break;
	default:
		return -_EPKTTYPE << 16 |
			pkt_type;
	}
	rmb();
	if (unlikely(pkt_type != dst->udib1.pkt_type))
		return -_EPKTTYPECHECK << 16 |
			dst->udib1.pkt_type << 8 |
			pkt_type;
	return 0;
}

enum ppe_l34_ecode {
	_EPROTO = 2,
	_EIPFRAG,
	_EIPPROTO,
	_EIPPKTTYPE,
	_EIPIP6PROTO,
	_EIP6PROTO,
	_EIP6PKTTYPE,
	_EIP6IPFRAG,
	_EIP6IPPROTO,
	_EIP6IPPKTTYPE,
	_EIP6IPMAPE,
	_EIP6NAPT,
	_EIP6EN,
};

int ppe_fill_L34_info(struct foe_entry *entry, struct sk_buff *skb,
				  const u8 *data, __be16 protocol) {
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct tcpudphdr *pptr;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	ct = nf_ct_get(skb, &ctinfo);

	switch (protocol) {
	case htons(ETH_P_IP):
		iph = (struct iphdr *)data;
		/* Do not bind if pkt is fragmented */
		if (ip_is_fragment(iph))
			return -_EIPFRAG << 24 |
				iph->protocol;

		switch (iph->protocol) {
		case IPPROTO_UDP:
			entry->bfib1.udp = 1;
			/* fallthrough */
		case IPPROTO_TCP:
		//case IPPROTO_GRE:
			switch (entry->bfib1.pkt_type) {
#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
			case IPV4_MAP_E:
				pptr = (struct tcpudphdr *)((u8 *)iph + iph->ihl * 4);
				entry->ipv4_mape.new_sport = ntohs(pptr->src);
				entry->ipv4_mape.new_dport = ntohs(pptr->dst);
				entry->ipv4_mape.new_sip = ntohl(iph->saddr);
				entry->ipv4_mape.new_dip = ntohl(iph->daddr);
				/* fallthrough */
#endif
			case IPV4_DSLITE:
				/* DS-Lite WAN->LAN */
				entry->ipv4_dslite.bfib1.rmt = 1;
				/*entry->ipv4_dslite.sip = foe->ipv4_dslite.sip;
				entry->ipv4_dslite.dip = foe->ipv4_dslite.dip;
				entry->ipv4_dslite.sport =
					foe->ipv4_dslite.sport;
				entry->ipv4_dslite.dport =
					foe->ipv4_dslite.dport;

				entry->ipv4_dslite.tunnel_sipv6_0 =
					foe->ipv4_dslite.tunnel_sipv6_0;
				entry->ipv4_dslite.tunnel_sipv6_1 =
					foe->ipv4_dslite.tunnel_sipv6_1;
				entry->ipv4_dslite.tunnel_sipv6_2 =
					foe->ipv4_dslite.tunnel_sipv6_2;
				entry->ipv4_dslite.tunnel_sipv6_3 =
					foe->ipv4_dslite.tunnel_sipv6_3;

				entry->ipv4_dslite.tunnel_dipv6_0 =
					foe->ipv4_dslite.tunnel_dipv6_0;
				entry->ipv4_dslite.tunnel_dipv6_1 =
					foe->ipv4_dslite.tunnel_dipv6_1;
				entry->ipv4_dslite.tunnel_dipv6_2 =
					foe->ipv4_dslite.tunnel_dipv6_2;
				entry->ipv4_dslite.tunnel_dipv6_3 =
					foe->ipv4_dslite.tunnel_dipv6_3;*/

				/*entry->ipv4_dslite.flow_lbl[] =
					foe->ipv4_dslite.flow_lbl[];
				entry->ipv4_dslite.priority =
					foe->ipv4_dslite.priority;
				entry->ipv4_dslite.hop_limit =
					foe->ipv4_dslite.hop_limit;*/

				/*entry->ipv4_dslite.etype = htons(ETH_P_IP);*/
				entry->ipv4_dslite.iblk2.dscp = iph->tos;
				break;
			case IPV4_HNAPT:
				pptr = (struct tcpudphdr *)((u8 *)iph + iph->ihl * 4);
				entry->ipv4_hnapt.new_sport = ntohs(pptr->src);
				entry->ipv4_hnapt.new_dport = ntohs(pptr->dst);
				/*entry->ipv4_hnapt.sport = foe->ipv4_hnapt.sport;
				entry->ipv4_hnapt.dport = foe->ipv4_hnapt.dport;*/
				/* fallthrough */
			case IPV4_HNAT:
				/* IPv4 WAN<->LAN */
				entry->ipv4_hnapt.new_sip = ntohl(iph->saddr);
				entry->ipv4_hnapt.new_dip = ntohl(iph->daddr);
				/*entry->ipv4_hnapt.sip = foe->ipv4_hnapt.sip;
				entry->ipv4_hnapt.dip = foe->ipv4_hnapt.dip;*/

				/*entry->ipv4_hnapt.etype = htons(ETH_P_IP);*/
				entry->ipv4_hnapt.iblk2.dscp = iph->tos;
				break;
			default:
				return -_EIPPKTTYPE << 24 |
					entry->bfib1.pkt_type << 16 |
					iph->protocol;
			}
			break;

		case IPPROTO_IPV6: /* 6RD LAN->WAN */
			ip6h = (struct ipv6hdr *)((u8 *)iph + iph->ihl * 4);
			entry->bfib1.pkt_type = IPV6_6RD;
			/*entry->bfib1.udp = foe->udib1.udp;*/
			//entry->bfib1.udp = ip6h->nexthdr == NEXTHDR_UDP;
			/*entry->ipv6_6rd.ipv6_sip0 = foe->ipv6_6rd.ipv6_sip0;
			entry->ipv6_6rd.ipv6_sip1 = foe->ipv6_6rd.ipv6_sip1;
			entry->ipv6_6rd.ipv6_sip2 = foe->ipv6_6rd.ipv6_sip2;
			entry->ipv6_6rd.ipv6_sip3 = foe->ipv6_6rd.ipv6_sip3;

			entry->ipv6_6rd.ipv6_dip0 = foe->ipv6_6rd.ipv6_dip0;
			entry->ipv6_6rd.ipv6_dip1 = foe->ipv6_6rd.ipv6_dip1;
			entry->ipv6_6rd.ipv6_dip2 = foe->ipv6_6rd.ipv6_dip2;
			entry->ipv6_6rd.ipv6_dip3 = foe->ipv6_6rd.ipv6_dip3;

			entry->ipv6_6rd.sport = foe->ipv6_6rd.sport;
			entry->ipv6_6rd.dport = foe->ipv6_6rd.dport;*/
			entry->ipv6_6rd.tunnel_sipv4 = ntohl(iph->saddr);
			entry->ipv6_6rd.tunnel_dipv4 = ntohl(iph->daddr);

			entry->ipv6_6rd.hdr_chksum = ppe_get_chkbase(iph);
			entry->ipv6_6rd.dscp = iph->tos;
			entry->ipv6_6rd.ttl = iph->ttl;
			entry->ipv6_6rd.flag = ntohs(iph->frag_off) >> 13;
			entry->ipv6_6rd.per_flow_6rd_id = 1;

			/*entry->ipv6_6rd.etype = htons(ETH_P_IP);*/
			/*entry->ipv6_6rd.iblk2.dscp = foe->ipv6_6rd.iblk2.dscp;*/
			entry->ipv6_6rd.iblk2.dscp =
				ip6h->priority << 4 |
				ip6h->flow_lbl[0] >> 4;
			// FIXME: iph->id = 0;
			//break;

		default:
			return -_EIPPROTO << 24 |
				iph->protocol;
		}

#if DEBUG_TRACE
		trace_printk(
			"[%s]skb->head=%p, skb->data=%p,ip_hdr=%p, skb->len=%d, skb->data_len=%d\n",
			__func__, skb->head, skb->data, iph, skb->len,
			skb->data_len);
#endif
		break;

	case htons(ETH_P_IPV6):
		ip6h = (struct ipv6hdr *)data;
		if (!hnat_priv->ipv6_en)
			return -_EIP6EN << 24 |
				ip6h->nexthdr;

		switch (ip6h->nexthdr) {
		case NEXTHDR_UDP:
			entry->bfib1.udp = 1;
			/* fallthrough */
		case NEXTHDR_TCP: /* IPv6-5T or IPv6-3T */
			switch (entry->bfib1.pkt_type) {
			case IPV6_6RD:
				entry->ipv6_6rd.bfib1.rmt = 1;
				/*entry->ipv6_6rd.tunnel_sipv4 =
					foe->ipv6_6rd.tunnel_sipv4;
				entry->ipv6_6rd.tunnel_dipv4 =
					foe->ipv6_6rd.tunnel_dipv4;*/
				/*entry->ipv6_6rd.dscp = foe->ipv6_6rd.dscp;*/
				/* fallthrough */
			case IPV6_5T_ROUTE:
				/*entry->ipv6_5t_route.sport =
					foe->ipv6_5t_route.sport;
				entry->ipv6_5t_route.dport =
					foe->ipv6_5t_route.dport;*/
			case IPV6_3T_ROUTE:
				/*entry->ipv6_3t_route.ipv6_sip0 =
					foe->ipv6_3t_route.ipv6_sip0;
				entry->ipv6_3t_route.ipv6_sip1 =
					foe->ipv6_3t_route.ipv6_sip1;
				entry->ipv6_3t_route.ipv6_sip2 =
					foe->ipv6_3t_route.ipv6_sip2;
				entry->ipv6_3t_route.ipv6_sip3 =
					foe->ipv6_3t_route.ipv6_sip3;

				entry->ipv6_3t_route.ipv6_dip0 =
					foe->ipv6_3t_route.ipv6_dip0;
				entry->ipv6_3t_route.ipv6_dip1 =
					foe->ipv6_3t_route.ipv6_dip1;
				entry->ipv6_3t_route.ipv6_dip2 =
					foe->ipv6_3t_route.ipv6_dip2;
				entry->ipv6_3t_route.ipv6_dip3 =
					foe->ipv6_3t_route.ipv6_dip3;*/

				/*entry->ipv6_3t_route.prot =
					foe->ipv6_3t_route.prot;
				entry->ipv6_3t_route.hph =
					foe->ipv6_3t_route.hph;*/

				/*entry->ipv6_5t_route.etype = htons(ETH_P_IPV6);*/
				entry->ipv6_5t_route.iblk2.dscp =
					ip6h->priority << 4 |
					ip6h->flow_lbl[0] >> 4;
				break;
			default:
				return -_EIP6PKTTYPE << 24 |
					entry->bfib1.pkt_type << 16 |
					ip6h->nexthdr;
			}
			if (ct) {
				bool dnat = CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL;
				switch (ct->status & IPS_NAT_MASK) {
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
				case IPS_SRC_NAT:
					dnat = !dnat;
					/* fallthrough */
				case IPS_DST_NAT:
					entry->bfib1.pkt_type = IPV6_HNAPT;
					pptr = (struct tcpudphdr *)((u8 *)ip6h + sizeof(*ip6h));
					entry->ipv6_hnapt.new_sport = ntohs(pptr->src);
					entry->ipv6_hnapt.new_dport = ntohs(pptr->dst);

					if (!dnat) {
						entry->ipv6_hnapt.eg_ipv6_dir =
							IPV6_SNAT;
						entry->ipv6_hnapt.new_ipv6_ip0 =
							ntohl(ip6h->saddr.s6_addr32[0]);
						entry->ipv6_hnapt.new_ipv6_ip1 =
							ntohl(ip6h->saddr.s6_addr32[1]);
						entry->ipv6_hnapt.new_ipv6_ip2 =
							ntohl(ip6h->saddr.s6_addr32[2]);
						entry->ipv6_hnapt.new_ipv6_ip3 =
							ntohl(ip6h->saddr.s6_addr32[3]);
					} else {
						entry->ipv6_hnapt.eg_ipv6_dir =
							IPV6_DNAT;
						entry->ipv6_hnapt.new_ipv6_ip0 =
							ntohl(ip6h->daddr.s6_addr32[0]);
						entry->ipv6_hnapt.new_ipv6_ip1 =
							ntohl(ip6h->daddr.s6_addr32[1]);
						entry->ipv6_hnapt.new_ipv6_ip2 =
							ntohl(ip6h->daddr.s6_addr32[2]);
						entry->ipv6_hnapt.new_ipv6_ip3 =
							ntohl(ip6h->daddr.s6_addr32[3]);
					}
					break;
#endif
				case 0:
					break;
				default:
					return -_EIP6NAPT << 24 |
						dnat << 23 |
						(ct->status & IPS_NAT_MASK);
				}
			}
			break;

		case NEXTHDR_IPIP:
			iph = (struct iphdr *)((u8 *)ip6h + sizeof(*ip6h));
			/* don't process inner fragment packets */
			if (ip_is_fragment(iph))
				return -_EIP6IPFRAG << 24 |
					iph->protocol;

			switch (iph->protocol) {
			case IPPROTO_UDP:
				entry->bfib1.udp = 1;
				/* fallthrough */
			case IPPROTO_TCP:
				break;
			default:
				return -_EIP6IPPROTO << 24 |
					iph->protocol;
			}

			switch (entry->bfib1.pkt_type) {
			case IPV4_HNAPT:
				if (!mape_toggle) {
					/* DS-Lite LAN->WAN */
					entry->bfib1.pkt_type = IPV4_DSLITE;
					break;
				}
#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
				/* Map-E LAN->WAN record inner IPv4 header info. */
				entry->bfib1.pkt_type = IPV4_MAP_E;
				pptr = (struct tcpudphdr *)((u8 *)iph + iph->ihl * 4);
				entry->ipv4_mape.new_sport = ntohs(pptr->src);
				entry->ipv4_mape.new_dport = ntohs(pptr->dst);
				entry->ipv4_mape.new_sip = ntohl(iph->saddr);
				entry->ipv4_mape.new_dip = ntohl(iph->daddr);
				break;
#else
				pptr = (struct tcpudphdr *)((u8 *)iph + iph->ihl * 4);
				entry->ipv4_hnapt.new_sport = ntohs(pptr->src);
				entry->ipv4_hnapt.new_dport = ntohs(pptr->dst);
				/*entry->ipv4_hnapt.sport = foe->ipv4_hnapt.sport;
				entry->ipv4_hnapt.dport = foe->ipv4_hnapt.dport;*/
				/* fallthrough */
			case IPV4_HNAT:
				/* MapE LAN -> WAN */
				entry->ipv4_hnapt.new_sip = ntohl(iph->saddr);
				entry->ipv4_hnapt.new_dip = ntohl(iph->daddr);
				/*entry->ipv4_hnapt.sip = foe->ipv4_hnapt.sip;
				entry->ipv4_hnapt.dip = foe->ipv4_hnapt.dip;*/

				/*entry->ipv4_hnapt.etype = htons(ETH_P_IP);*/
				entry->ipv4_hnapt.iblk2.dscp = iph->tos;
				mape_l2w_v6h = *ip6h;
				return -_EIP6IPMAPE << 24;
#endif
			default:
				return -_EIP6IPPKTTYPE << 24 |
					mape_toggle << 23 |
					entry->bfib1.pkt_type << 16 |
					iph->protocol;
			}
			/*entry->ipv4_dslite.sip = foe->ipv4_dslite.sip;
			entry->ipv4_dslite.dip = foe->ipv4_dslite.dip;
			entry->ipv4_dslite.sport =
				foe->ipv4_dslite.sport;
			entry->ipv4_dslite.dport =
				foe->ipv4_dslite.dport;*/

			entry->ipv4_dslite.tunnel_sipv6_0 =
				ntohl(ip6h->saddr.s6_addr32[0]);
			entry->ipv4_dslite.tunnel_sipv6_1 =
				ntohl(ip6h->saddr.s6_addr32[1]);
			entry->ipv4_dslite.tunnel_sipv6_2 =
				ntohl(ip6h->saddr.s6_addr32[2]);
			entry->ipv4_dslite.tunnel_sipv6_3 =
				ntohl(ip6h->saddr.s6_addr32[3]);

			entry->ipv4_dslite.tunnel_dipv6_0 =
				ntohl(ip6h->daddr.s6_addr32[0]);
			entry->ipv4_dslite.tunnel_dipv6_1 =
				ntohl(ip6h->daddr.s6_addr32[1]);
			entry->ipv4_dslite.tunnel_dipv6_2 =
				ntohl(ip6h->daddr.s6_addr32[2]);
			entry->ipv4_dslite.tunnel_dipv6_3 =
				ntohl(ip6h->daddr.s6_addr32[3]);

			ppe_fill_flow_lbl(entry, ip6h);
			entry->ipv4_dslite.priority = ip6h->priority;
			entry->ipv4_dslite.hop_limit = ip6h->hop_limit;

			/*entry->ipv4_dslite.etype = htons(ETH_P_IPV6);*/
			entry->ipv4_dslite.iblk2.dscp = iph->tos;
			break;

		default:
			return -_EIP6PROTO << 24 |
				ip6h->nexthdr;
		}

#if DEBUG_TRACE
		trace_printk(
			"[%s]skb->head=%p, skb->data=%p,ipv6_hdr=%p, skb->len=%d, skb->data_len=%d\n",
			__func__, skb->head, skb->data, ip6h, skb->len,
			skb->data_len);
#endif
		break;

	default:
		return -_EPROTO << 24 |
			protocol;
	}

	return 0;
}

static int ppe_fill_info_blk2(struct foe_entry *entry, struct sk_buff *skb) {
	union {
		struct hnat_info_blk2 iblk2;
		struct hnat_info_blk2_whnat iblk2w;
		u32 info_blk2;
	} iblk2;
	struct foe_entry *vlan1;
	u32 qid;

	/* align to vlan1 */
	if (IS_IPV4_GRP(entry)) {
		iblk2.info_blk2 = entry->ipv4_hnapt.info_blk2;
		vlan1 = container_of(&entry->ipv4_hnapt.vlan1,
			struct foe_entry, ipv6_5t_route.vlan1);
	} else {
		iblk2.info_blk2 = entry->ipv6_5t_route.info_blk2;
		vlan1 = container_of(&entry->ipv6_5t_route.vlan1,
			struct foe_entry, ipv6_5t_route.vlan1);
	}

	iblk2.iblk2.mibf = hnat_priv->data->per_flow_accounting;
#if !(defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3))
	iblk2.iblk2.port_mg =
		(hnat_priv->data->version == MTK_HNAT_V1_1) ? -1 : 0;
#endif
	iblk2.iblk2.port_ag = -1;

	if (qos_toggle) {
		if (skb->mark < MAX_PPPQ_PORT_NUM &&
		    IS_PPPQ_MODE && IS_PPPQ_PATH(skb->dev, skb))
			qid = (vlan1->ipv6_5t_route.vlan1 & VLAN_VID_MASK) % MAX_PPPQ_PORT_NUM;
		else
			qid = skb->mark;
#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
		iblk2.iblk2.qid = qid & 0x7f;
#else
		/* qid[5:0]= port_mg[1:0]+ qid[3:0] */
		iblk2.iblk2.qid = qid & 0xf;
		if (hnat_priv->data->version != MTK_HNAT_V1_1)
			iblk2.iblk2w.qid2 = (qid >> 4) & 0x3;
#endif
	}

	switch (iblk2.iblk2.dp) {
#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
	case NR_WDMA0_PORT:
	case NR_WDMA1_PORT:
	case NR_WDMA2_PORT:
		{
			iblk2.iblk2.rxid = skb_hnat_rx_id(skb);
			iblk2.iblk2.winfoi = 1;
#else
	case NR_WHNAT_WDMA_PORT:
		/* multicast flow not go to WDMA */
		if (iblk2.iblk2.mcast ||
		    unlikely(entry->bfib1.vlan_layer >= 2)) {
			/* fallthrough */
		} else if (likely(hnat_priv->data->version == MTK_HNAT_V1_2)) {
			/* The INFO2.port_mg and 2nd VLAN ID fields of PPE entry are redefined
			 * by Wi-Fi whnat engine. These data and INFO2.dp will be updated and
			 * the entry is set to BIND state in mtk_sw_nat_hook_tx().
			 */
			iblk2.iblk2w.wdmaid = skb_hnat_wdma_id(skb);
			iblk2.iblk2w.winfoi = 1;
			vlan1->ipv6_5t_route.winfo.rxid = skb_hnat_rx_id(skb);
#endif
			/* MT7622 wifi hw_nat not support QoS */
			/*iblk2.iblk2.fqos = 0;*/
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
			if (IS_IPV4_MAPE(entry)) {
				vlan1->ipv4_mape.tport_id = IS_HQOS_DL_MODE ? 1 : 0;
				vlan1->ipv4_mape.winfo_pao.usr_info =
					skb_hnat_usr_info(skb);
				vlan1->ipv4_mape.winfo_pao.tid =
					skb_hnat_tid(skb);
				vlan1->ipv4_mape.winfo_pao.is_fixedrate =
					skb_hnat_is_fixedrate(skb);
				vlan1->ipv4_mape.winfo_pao.is_prior =
					skb_hnat_is_prior(skb);
				vlan1->ipv4_mape.winfo_pao.is_sp =
					skb_hnat_is_sp(skb);
				vlan1->ipv4_mape.winfo_pao.hf =
					skb_hnat_hf(skb);
				vlan1->ipv4_mape.winfo_pao.amsdu =
					skb_hnat_amsdu(skb);
				vlan1->ipv4_mape.winfo.bssid = skb_hnat_bss_id(skb);
				vlan1->ipv4_mape.winfo.wcid = skb_hnat_wc_id(skb);
				break;
			} else if (IS_IPV6_HNAPT(entry) || IS_IPV6_HNAT(entry)) {
				vlan1->ipv6_hnapt.tport_id = IS_HQOS_DL_MODE ? 1 : 0;
				vlan1->ipv6_hnapt.winfo_pao.usr_info =
					skb_hnat_usr_info(skb);
				vlan1->ipv6_hnapt.winfo_pao.tid =
					skb_hnat_tid(skb);
				vlan1->ipv6_hnapt.winfo_pao.is_fixedrate =
					skb_hnat_is_fixedrate(skb);
				vlan1->ipv6_hnapt.winfo_pao.is_prior =
					skb_hnat_is_prior(skb);
				vlan1->ipv6_hnapt.winfo_pao.is_sp =
					skb_hnat_is_sp(skb);
				vlan1->ipv6_hnapt.winfo_pao.hf =
					skb_hnat_hf(skb);
				vlan1->ipv6_hnapt.winfo_pao.amsdu =
					skb_hnat_amsdu(skb);
				vlan1->ipv6_hnapt.winfo.bssid = skb_hnat_bss_id(skb);
				vlan1->ipv6_hnapt.winfo.wcid = skb_hnat_wc_id(skb);
				break;
			}
			vlan1->ipv6_5t_route.tport_id = IS_HQOS_DL_MODE ? 1 : 0;
			vlan1->ipv6_5t_route.winfo_pao.usr_info =
				skb_hnat_usr_info(skb);
			vlan1->ipv6_5t_route.winfo_pao.tid =
				skb_hnat_tid(skb);
			vlan1->ipv6_5t_route.winfo_pao.is_fixedrate =
				skb_hnat_is_fixedrate(skb);
			vlan1->ipv6_5t_route.winfo_pao.is_prior =
				skb_hnat_is_prior(skb);
			vlan1->ipv6_5t_route.winfo_pao.is_sp =
				skb_hnat_is_sp(skb);
			vlan1->ipv6_5t_route.winfo_pao.hf =
				skb_hnat_hf(skb);
			vlan1->ipv6_5t_route.winfo_pao.amsdu =
				skb_hnat_amsdu(skb);
			/* fallthrough */
#endif
			vlan1->ipv6_5t_route.winfo.bssid = skb_hnat_bss_id(skb);
			vlan1->ipv6_5t_route.winfo.wcid = skb_hnat_wc_id(skb);
			break;
		}
#if defined(CONFIG_RAETH_QDMATX_QDMARX) || defined(CONFIG_RAETH_PDMATX_QDMARX)
	case NR_PDMA_PORT:
		iblk2.iblk2.dp = NR_QDMA_PORT;
	case NR_QDMA_PORT:
#else
	case NR_QDMA_PORT:
		iblk2.iblk2.dp = NR_PDMA_PORT;
	case NR_PDMA_PORT:
#endif
		/* wifi to wifi not go to pse port */
		if (skb_hnat_reentry(skb) ||
		    skb_hnat_sport(skb) == NR_QDMA_PORT ||
		    unlikely(entry->bfib1.vlan_layer >= 2)) {
			/* fallthrough */
		} else if (IS_HQOS_MODE) {
			entry->bfib1.vlan_layer++;
			/*entry->bfib1.vpm = 0;*/
			iblk2.iblk2.fqos = 1;
			vlan1->ipv6_5t_route.etype = ntohs(HQOS_MAGIC_TAG);
			vlan1->ipv6_5t_route.vlan2 = vlan1->ipv6_5t_route.vlan1;
			vlan1->ipv6_5t_route.vlan1 = ntohs(skb_hnat_entry(skb));
			break;
		}
		/*iblk2.iblk2.fqos = 0;*/
		break;
	case NR_GMAC1_PORT:
	case NR_GMAC2_PORT:
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
	case NR_GMAC3_PORT:
#endif
		if (skb_hnat_reentry(skb) ||
		    skb_hnat_sport(skb) == NR_QDMA_PORT) {
			/* fallthrough */
		} else if ((IS_PPPQ_MODE &&
		     IS_PPPQ_PATH(skb->dev, skb)) ||
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
		    (IS_HQOS_UL_MODE && (skb_hnat_iface(skb) & 0x40) == 0x40) ||
		    (IS_HQOS_DL_MODE && (skb_hnat_iface(skb) & 0x70) == 0x20)) {
			/*iblk2.iblk2.fqos = 0;*/
			if (IS_IPV4_MAPE(entry)
				vlan1->ipv4_mape.tport_id = 1;
			else if (IS_IPV6_HNAPT(entry) || IS_IPV6_HNAT(entry))
				vlan1->ipv6_hnapt.tport_id = 1;
			else
				vlan1->ipv6_5t_route.tport_id = 1;
			break;
		} /*else if (IS_HQOS_MODE) {
			iblk2.iblk2.fqos = 1;
			if (IS_IPV4_MAPE(entry)
				vlan1->ipv4_mape.tport_id = 0;
			else if (IS_IPV6_HNAPT(entry) || IS_IPV6_HNAT(entry))
				vlan1->ipv6_hnapt.tport_id = 0;
			else
				vlan1->ipv6_5t_route.tport_id = 0;
			break;
		}*/
		/*if (IS_IPV4_MAPE(entry)
			vlan1->ipv4_mape.tport_id = 0;
		else if (IS_IPV6_HNAPT(entry) || IS_IPV6_HNAT(entry))
			vlan1->ipv6_hnapt.tport_id = 0;
		else
			vlan1->ipv6_5t_route.tport_id = 0;*/
#else
		    IS_HQOS_MODE) {
			iblk2.iblk2.fqos = 1;
			break;
		}
#endif
		/*iblk2.iblk2.fqos = 0;*/
		break;
	default:
		return -_EDPORT << 16 |
			entry->bfib1.pkt_type << 8 |
			iblk2.iblk2.dp;
	}

	if (IS_IPV4_GRP(entry))
		entry->ipv4_hnapt.info_blk2 = iblk2.info_blk2;
	else
		entry->ipv6_5t_route.info_blk2 = iblk2.info_blk2;

	return 0;
}

enum ppe_ecode {
	_EEXTDEV = 2,
	_EWANDEV,
	_EBOUND,
	_EBOUNDCHECK,
};

int skb_to_hnat_info(struct foe_entry *foe, struct sk_buff *skb, int gmac_no) {
	struct foe_entry entry;
	u16 vlan[2] = { 0 }, pppoe_id = 0, etype, index;
	u8 vlan_layer = 0;
	int ret;

	const struct ethhdr *eth = (struct ethhdr *)skb->data;
	const u8 *data = (u8 *)eth + ETH_HLEN;
	__be16 protocol = eth->h_proto;

	if (entry_hnat_is_bound(foe))
		return -_EBOUND;

	/*not bind multicast if PPE mcast not enable*/
	if (!hnat_priv->data->mcast)
		if (is_multicast_ether_addr(eth->h_dest))
			return -_EMCAST << 16;

	if (gmac_no != NR_PDMA_PORT &&
	    gmac_no != NR_QDMA_PORT)
		index = -1;
	else if (IS_WAN(skb->dev) &&
		     (skb_hnat_iface(skb) |= 0x40, mape_toggle))
		/* Set act_dp = wan_dev */
		index = 0;
	else if ((index = get_index_from_dev(skb->dev)) == 0 ||
		     IS_WHNAT(skb->dev))
		return -_EEXTDEV;

	ret = ppe_copy_foe_entry(&entry, foe, 0);
	if (ret < 0)
		return ret;

	if (unlikely(entry_hnat_is_bound(&entry)))
		return -_EBOUNDCHECK;

	/* HW VLAN */
	if (skb_vlan_tag_present(skb)) {
		etype = ntohs(skb->vlan_proto);
		vlan[vlan_layer++] =
			skb_vlan_tag_get(skb);
	} else
		etype = ntohs(protocol);

	/* VLAN + VLAN */
	for (; protocol == htons(ETH_P_8021Q) && likely(vlan_layer < 2);) {
		struct vlan_hdr *vhdr = (struct vlan_hdr *)data;
		protocol = vhdr->h_vlan_encapsulated_proto;
		vlan[vlan_layer++] =
			ntohs(vhdr->h_vlan_TCI);
		data = (u8 *)vhdr + VLAN_HLEN;
	}

	entry.bfib1.time_stamp =
#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
		readl(hnat_priv->fe_base + 0x0010) & (0xFF);
	entry.bfib1.mc = 0;
#else
		readl(hnat_priv->fe_base + 0x0010) & (0x7FFF);
#endif
	entry.bfib1.ka = 1;
	entry.bfib1.vlan_layer = vlan_layer;
	entry.bfib1.psn = 0;
	/* HNAT_V2 can push special tag */
	entry.bfib1.vpm = 0;
	entry.bfib1.ps = 0;
	entry.bfib1.cah = 1;
	entry.bfib1.rmt = 0;
	entry.bfib1.ttl = 1;
	entry.bfib1.state = BIND;
	// FIXME:
	entry.bfib1.udp = 0;

	/* PPPoE + IP */
	if (protocol == htons(ETH_P_PPP_SES)) {
		struct pppoe_hdr *ph = (struct pppoe_hdr *)data;
		if (unlikely(ph->ver != 1 || ph->type != 1))
			return -_EPPPOE << 16 |
				ph->ver << 4 |
				ph->type;
		switch (ph->tag[0].tag_type) {
		case htons(PPP_IP):
			protocol = htons(ETH_P_IP);
			break;
		case htons(PPP_IPV6):
			protocol = htons(ETH_P_IPV6);
			break;
		default:
			return -_EPPPPROTO << 16 |
				ph->tag[0].tag_type;
		}
		entry.bfib1.psn = 1;
		pppoe_id = ntohs(ph->sid);
		data = (u8 *)ph + PPPOE_SES_HLEN;
	}

	ret = ppe_fill_L34_info(&entry, skb, data, protocol);
	if (ret < 0) {
		if (index != 0 || ret != -_EIP6IPMAPE << 24) {
			return ret;
		}
	} else if (index == 0) {
		if ((index = get_index_from_dev(skb->dev)) == 0 ||
		    IS_WHNAT(skb->dev))
			return -_EWANDEV;
	} else if (index == (u16)-1)
		index = 0;

	/* Fill Layer2 Info.*/
	if (IS_IPV4_GRP(&entry)) {
		entry.ipv4_hnapt.act_dp = index;
		entry.ipv4_hnapt.vlan1 = vlan[0];
		entry.ipv4_hnapt.vlan2 = vlan[1];
		entry.ipv4_hnapt.pppoe_id = pppoe_id;
		entry.ipv4_hnapt.etype = etype;
		entry.ipv4_hnapt.dmac_hi = ntohl(*((u32 *)&eth->h_dest[0]));
		entry.ipv4_hnapt.dmac_lo = ntohs(*((u16 *)&eth->h_dest[4]));
		entry.ipv4_hnapt.smac_hi = ntohl(*((u32 *)&eth->h_source[0]));
		entry.ipv4_hnapt.smac_lo = ntohs(*((u16 *)&eth->h_source[4]));
		if (hnat_priv->data->mcast &&
		    is_multicast_ether_addr(&eth->h_dest[0])) {
			entry.ipv4_hnapt.iblk2.mcast = 1;
#if !(defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3))
			if (hnat_priv->data->version == MTK_HNAT_V1_3) {
				entry.bfib1.sta = 1;
				entry.ipv4_hnapt.m_timestamp = foe_timestamp(hnat_priv);
			}
#endif
		} /*else {
			entry.ipv4_hnapt.iblk2.mcast = 0;
		}*/
		entry.ipv4_hnapt.iblk2.dp = gmac_no;
	} else {
		entry.ipv6_5t_route.act_dp = index;
		entry.ipv6_5t_route.vlan1 = vlan[0];
		entry.ipv6_5t_route.vlan2 = vlan[1];
		entry.ipv6_5t_route.pppoe_id = pppoe_id;
		entry.ipv6_5t_route.etype = etype;
		entry.ipv6_5t_route.dmac_hi = ntohl(*((u32 *)&eth->h_dest[0]));
		entry.ipv6_5t_route.dmac_lo = ntohs(*((u16 *)&eth->h_dest[4]));
		entry.ipv6_5t_route.smac_hi = ntohl(*((u32 *)&eth->h_source[0]));
		entry.ipv6_5t_route.smac_lo = ntohs(*((u16 *)&eth->h_source[4]));
		if (hnat_priv->data->mcast &&
		    is_multicast_ether_addr(&eth->h_dest[0])) {
			entry.ipv6_5t_route.iblk2.mcast = 1;
#if !(defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3))
			if (hnat_priv->data->version == MTK_HNAT_V1_3) {
				entry.bfib1.sta = 1;
				// FIXME:
				entry.ipv4_hnapt.m_timestamp = foe_timestamp(hnat_priv);
			}
#endif
		} /*else {
			entry.ipv6_5t_route.iblk2.mcast = 0;
		}*/
		entry.ipv6_5t_route.iblk2.dp = gmac_no;
	}

	/* Fill Info Blk*/
	ret = ppe_fill_info_blk2(&entry, skb);
	if (ret < 0) {
		return ret;
	}

	wmb();
	memcpy(foe, &entry, sizeof(struct foe_entry));
	/*reset statistic for this entry*/
	if (hnat_priv->data->per_flow_accounting)
		memset(&hnat_priv->acct[skb_hnat_ppe(skb)][skb_hnat_entry(skb)],
		       0, sizeof(struct mib_entry));

	return 0;
}

//static int mtk_hnat_accel_type(struct sk_buff *skb);
static void mtk_hnat_nf_update(struct sk_buff *skb);
static void mtk_hnat_dscp_update(struct sk_buff *skb, struct foe_entry *entry);
int mtk_sw_nat_hook_tx(struct sk_buff *skb, int gmac_no)
{
	u8 reason;

	if (!is_magic_tag_valid(skb) ||
	    unlikely(skb_headroom(skb) < FOE_INFO_LEN))
		return NF_ACCEPT;

	reason = skb_hnat_reason(skb);
	if (!skb_hnat_alg(skb) && likely(skb_hnat_iface(skb) < 0x70 &&
	    skb_hnat_entry(skb) < hnat_priv->foe_etry_num &&
	    skb_hnat_ppe(skb) < CFG_PPE_NUM &&
	    skb_hnat_is_hashed(skb))) {
		int ret;
		struct foe_entry *entry =
			&hnat_priv->foe_table_cpu[skb_hnat_ppe(skb)][skb_hnat_entry(skb)];

		switch (reason) {
		case HIT_UNBIND_RATE_REACH:
			if (unlikely(!skb_mac_header_was_set(skb)))
				return NF_ACCEPT;

			/*if (fn && !mtk_hnat_accel_type(skb))
				return NF_ACCEPT;*/

#if DEBUG_TRACE
			trace_printk(
				"[%s]entry=%x reason=%x gmac_no=%x wdmaid=%x rxid=%x wcid=%x bssid=%x\n",
				__func__, skb_hnat_entry(skb), skb_hnat_reason(skb), gmac_no,
				skb_hnat_wdma_id(skb), skb_hnat_bss_id(skb),
				skb_hnat_wc_id(skb), skb_hnat_rx_id(skb));
#endif
			ret = skb_to_hnat_info(entry, skb, gmac_no);
			if (ret < -_EWANDEV) {
				skb_hnat_alg(skb) = 1;
/*
				if (ret < -_EPKTTYPECHECK << 16)
					printk(KERN_WARNING
						"hook_tx(out_dev=%s, ret=0x%x)\n",
						skb->dev->name, ret);
*/
			}
			return NF_ACCEPT;
		//cast HIT_BIND_KEEPALIVE_MC_NEW_HDR:
		case HIT_BIND_KEEPALIVE_DUP_OLD_HDR:
			if (!entry_hnat_is_bound(entry))
				break;

			/* update hnat count to nf_conntrack by keepalive */
			if (hnat_priv->nf_stat_en &&
				hnat_priv->data->per_flow_accounting)
				mtk_hnat_nf_update(skb);

			/*if (fn && !mtk_hnat_accel_type(skb))
				break;*/

			/* update dscp for qos */
			mtk_hnat_dscp_update(skb, entry);

#if !(defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3))
			/* update mcast timestamp*/
			if (hnat_priv->data->mcast &&
				hnat_priv->data->version == MTK_HNAT_V1_3 &&
				entry->bfib1.sta == 1)
				// FIXME:
				entry->ipv4_hnapt.m_timestamp = foe_timestamp(hnat_priv);
#endif
			break;
		}
	}

	switch (reason) {
	//cast HIT_BIND_KEEPALIVE_MC_NEW_HDR:
	case HIT_BIND_KEEPALIVE_DUP_OLD_HDR:
		/*if (entry_hnat_is_bound(entry)) {
			//memset(skb_hnat_info(skb), 0, sizeof(struct hnat_desc));
			memset(skb_hnat_info(skb), 0, FOE_INFO_LEN);

			return NF_DROP;
		}
		break;*/
		skb_hnat_alg(skb) = 1;
		return NF_DROP;
	case HIT_BIND_MULTICAST_TO_CPU:
	case HIT_BIND_MULTICAST_TO_GMAC_CPU:
		/*do not forward to gdma again,if ppe already done it*/
		switch (gmac_no) {
		case NR_GMAC1_PORT:
		case NR_GMAC2_PORT:
#if defined(CONFIG_MEDIATEK_NETSYS_V3)
		case NR_GMAC3_PORT:
#endif
			return NF_DROP;
		}
		break;
	}

	return NF_ACCEPT;
}

int mtk_sw_nat_hook_rx(struct sk_buff *skb)
{
	__u16 vlan_tci;
#if defined(CONFIG_FAST_NAT_SUPPORT)
	if (!is_magic_tag_valid(skb) ||
	    unlikely(skb_headroom(skb) < FOE_INFO_LEN + ETH_HLEN))
		return NF_ACCEPT;
#else
	if (unlikely(skb_headroom(skb) < FOE_INFO_LEN + ETH_HLEN))
		return NF_ACCEPT;
	else if (!is_magic_tag_valid(skb)) {
		clr_from_extge(skb);
		skb_hnat_alg(skb) = 0;
		skb_hnat_reason(skb) = UN_HIT;
		skb_hnat_iface(skb) = FOE_INVALID;
		skb_hnat_magic_tag(skb) = HNAT_MAGIC_TAG;
	}
#endif

	else if (skb_hnat_iface(skb) >= 0x70) {
		clr_from_extge(skb);
		skb_hnat_alg(skb) = 0;
		switch ((skb_hnat_iface(skb) -= 0x70) + 0x70) {
#if defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3)
		case FOE_MAGIC_WED0:
			skb_hnat_sport(skb) = NR_WDMA0_PORT;
			break;
		case FOE_MAGIC_WED1:
			skb_hnat_sport(skb) = NR_WDMA1_PORT;
			break;
		case FOE_MAGIC_WED2:
			skb_hnat_sport(skb) = NR_WDMA2_PORT;
			break;
#endif
		case FOE_MAGIC_GE:
			break;
#if defined(CONFIG_FAST_NAT_SUPPORT)
		case FOE_MAGIC_WLAN:
		case FOE_MAGIC_PCI:
			//skb_hnat_alg(skb) = 1;
			skb_hnat_reason(skb) = UN_HIT;
			goto ext2ge;
#endif
		default:
			/* do not accelerate original packet, try to go to ppe port */
			//skb_hnat_alg(skb) = 1;
			skb_hnat_reason(skb) = UN_HIT;
			return NF_ACCEPT;
		} {
			struct vlan_ethhdr *veth = (struct vlan_ethhdr *)__skb_push(skb, ETH_HLEN);
			__be16 vlan_proto = veth->h_vlan_proto;

			if (unlikely(debug_level >= 7)) {
				hnat_cpu_reason_cnt(skb);
				if (skb_hnat_reason(skb) == dbg_cpu_reason)
					foe_dump_pkt(skb);
			}

			if (vlan_proto == HQOS_MAGIC_TAG &&
			    likely(skb_hnat_sport(skb) == NR_QDMA_PORT)) {
				vlan_tci = remove_vlan_tag(skb);
				skb_hnat_entry(skb) = vlan_tci;
				skb_hnat_reason(skb) = HIT_BIND_FORCE_TO_CPU;
				goto ge2ext;
			}

			/* packets form ge -> external device */
			else if (skb_hnat_reason(skb) == HIT_BIND_FORCE_TO_CPU) {
				vlan_tci = skb_hnat_entry(skb);
ge2ext:
				if (likely(vlan_tci < hnat_priv->foe_etry_num &&
				    skb_hnat_ppe(skb) < CFG_PPE_NUM &&
				    skb_hnat_is_hashed(skb)) &&
				    !do_hnat_ge_to_ext(skb,
						&hnat_priv->foe_table_cpu[skb_hnat_ppe(skb)][vlan_tci], __func__))
					return NF_DROP;
				goto drop;
			}

			else if (skb_hnat_reason(skb) == HIT_BIND_KEEPALIVE_MC_NEW_HDR) {
				//keep_alive_handler(skb, entry);
			}

			/* packets from external devices -> xxx ,step 2, learning stage */
			else if (skb_hnat_sport(skb) == NR_PDMA_PORT ||
				     skb_hnat_sport(skb) == NR_QDMA_PORT) {
				if (skb_vlan_tag_present(skb)) {
					vlan_tci = skb->vlan_tci;
					skb->vlan_tci = 0;
					skb->vlan_proto = 0;
				} else if (vlan_proto == htons(ETH_P_8021Q))
					vlan_tci = ntohs(remove_vlan_tag(skb));
				else
					goto drop;
				if (!do_hnat_ext_to_ge2(skb, vlan_tci, __func__))
					return NF_DROP;
				goto drop;
			}
			__skb_pull(skb, ETH_HLEN);

			return NF_ACCEPT;
		}
	}

	/* MapE need remove ipv6 header and pingpong. */
	if (IS_WAN(skb->dev)) {
		skb_hnat_iface(skb) = FOE_MAGIC_GE_WAN;
#if !(defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3))
		if (mape_toggle && !is_from_mape(skb) &&
		    !is_broadcast_ether_addr(eth_hdr(skb)->h_dest) &&
		    !do_hnat_mape_w2l_fast(skb, skb->dev->ifindex, __func__))
			return NF_DROP;
#endif
	}

	/* packets from external devices -> xxx ,step 1 , learning stage & bound stage*/
	if (get_index_from_dev(skb->dev) != 0) {
ext2ge:
		//skb_hnat_iface(skb) = FOE_MAGIC_EXT;
		if (!is_from_extge(skb) &&
		    !is_multicast_ether_addr(eth_hdr(skb)->h_dest) &&
		    !do_hnat_ext_to_ge(skb, skb->dev->ifindex, __func__))
			return NF_DROP;
	}

	return NF_ACCEPT;
drop:
	if (skb) {
		printk_ratelimited(KERN_WARNING
			"%s:drop (in_dev=%s, iif=0x%x, CB2=0x%x, ppe_hash=0x%x,\n"
			"sport=0x%x, reason=0x%x, alg=0x%x)\n",
			__func__, skb->dev->name, skb_hnat_iface(skb),
			HNAT_SKB_CB2(skb)->magic, skb_hnat_entry(skb),
			skb_hnat_sport(skb), skb_hnat_reason(skb),
			skb_hnat_alg(skb));
		dev_kfree_skb_any(skb);
	}

	return NF_DROP;
}

void mtk_ppe_dev_register_hook(struct net_device *dev)
{
	size_t i;
	struct extdev_entry *ext_entry;

	//TODO:
	if (dev->name && !strncmp(dev->name, "wds", 3))
		return;

	if (!hnat_priv->guest_en && dev->name) {
		if (!strcmp(dev->name, "ra1") || !strcmp(dev->name, "rai1") || !strcmp(dev->name, "rax1"))
			return;
	}

	for (i = 0; i < MAX_IF_NUM; i++) {
		if (hnat_priv->wifi_hook_if[i] == dev) {
			pr_info("%s : %s has been registered in wifi_hook_if table[%d]\n",
				__func__, dev->name, i);
			return;
		}
	}

	for (i = 0; i < MAX_IF_NUM; i++) {
		if (!hnat_priv->wifi_hook_if[i]) {
			if (extif_set_dev(dev)) {
				goto add_wifi_hook_if;
			} else if (!ext_if_add(
				ext_entry = kzalloc(sizeof(*ext_entry), GFP_KERNEL))) {
				kfree(ext_entry);
				pr_info("%s : extdev array is full. %s is not registered\n",
					__func__, dev->name);
				return;
			}

			if (!ext_entry)
				return;

			dev_hold(dev);
			ext_entry->dev = dev;
			strncpy(ext_entry->name, dev->name, IFNAMSIZ - 1);

add_wifi_hook_if:
			dev_hold(dev);
			hnat_priv->wifi_hook_if[i] = dev;
			break;
		}
	}
	pr_info("%s : ineterface %s register (%d)\n", __func__, dev->name, i);
}

void mtk_ppe_dev_unregister_hook(struct net_device *dev)
{
	size_t i;

	for (i = 0; i < MAX_IF_NUM; i++) {
		if (hnat_priv->wifi_hook_if[i] == dev) {
			hnat_priv->wifi_hook_if[i] = NULL;
			dev_put(dev);
			extif_put_dev(dev);
			break;
		}
	}
	pr_info("%s : ineterface %s set null (%d)\n", __func__, dev->name, i);
}

static int mtk_hnat_accel_type(struct sk_buff *skb)
{
	struct dst_entry *dst;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	const struct nf_conn_help *help;

	/* Do not accelerate 1st round of xfrm flow, and 2nd round of xfrm flow
	 * is from local_out which is also filtered in sanity check.
	 */
	dst = skb_dst(skb);
	if (dst && dst_xfrm(dst))
		return 0;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return 1;

	/* rcu_read_lock()ed by nf_hook_slow */
	help = nfct_help(ct);
	if (help && rcu_dereference(help->helper))
		return 0;

	return 1;
}

static void mtk_hnat_dscp_update(struct sk_buff *skb, struct foe_entry *entry)
{
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	bool flag = false;

	eth = eth_hdr(skb);
	switch (eth->h_proto) {
	case htons(ETH_P_IP):
		iph = ip_hdr(skb);
		if (IS_IPV4_GRP(entry) && entry->ipv4_hnapt.iblk2.dscp != iph->tos)
			flag = true;
		break;
	case htons(ETH_P_IPV6):
		ip6h = ipv6_hdr(skb);
		if ((IS_IPV6_3T_ROUTE(entry) || IS_IPV6_5T_ROUTE(entry)) &&
			entry->ipv6_5t_route.iblk2.dscp !=
			(ip6h->priority << 4 | ip6h->flow_lbl[0] >> 4))
			flag = true;
		break;
	default:
		return;
	}

	if (flag && likely(entry_hnat_is_bound(entry))) {
		if (debug_level >= 2)
			pr_info("Delete entry idx=%d.\n", skb_hnat_entry(skb));
		//memset(entry, 0, sizeof(struct foe_entry));
		entry->udib1.state = INVALID;
		entry->udib1.time_stamp =
			readl((hnat_priv->fe_base + 0x0010)) & 0xFF;
		hnat_cache_ebl(1);
	}
}

static void mtk_hnat_nf_update(struct sk_buff *skb)
{
	struct nf_conn *ct;
	struct nf_conn_acct *acct;
	struct nf_conn_counter *counter;
	enum ip_conntrack_info ctinfo;
	struct hnat_accounting diff;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct) {
		if (!hnat_get_count(hnat_priv, skb_hnat_ppe(skb), skb_hnat_entry(skb), &diff))
			return;

		acct = nf_conn_acct_find(ct);
		if (acct) {
			counter = acct->counter;
			atomic64_add(diff.packets, &counter[CTINFO2DIR(ctinfo)].packets);
			atomic64_add(diff.bytes, &counter[CTINFO2DIR(ctinfo)].bytes);
		}
	}
}

int mtk_464xlat_fill_mac(struct foe_entry *entry, struct sk_buff *skb,
			 const struct net_device *out, bool l2w)
{
	const struct in6_addr *ipv6_nexthop;
	struct dst_entry *dst = skb_dst(skb);
	struct neighbour *neigh = NULL;
	struct rtable *rt = (struct rtable *)dst;
	u32 nexthop;

	rcu_read_lock_bh();
	if (l2w) {
		ipv6_nexthop = rt6_nexthop((struct rt6_info *)dst,
					   &ipv6_hdr(skb)->daddr);
		neigh = __ipv6_neigh_lookup_noref(dst->dev, ipv6_nexthop);
		if (unlikely(!neigh)) {
			dev_notice(hnat_priv->dev, "%s:No neigh (daddr=%pI6)\n",
				   __func__, &ipv6_hdr(skb)->daddr);
			rcu_read_unlock_bh();
			return -1;
		}
	} else {
		nexthop = (__force u32)rt_nexthop(rt, ip_hdr(skb)->daddr);
		neigh = __ipv4_neigh_lookup_noref(dst->dev, nexthop);
		if (unlikely(!neigh)) {
			dev_notice(hnat_priv->dev, "%s:No neigh (daddr=%pI4)\n",
				   __func__, &ip_hdr(skb)->daddr);
			rcu_read_unlock_bh();
			return -1;
		}
	}
	rcu_read_unlock_bh();

	entry->ipv4_dslite.dmac_hi = swab32(*((u32 *)neigh->ha));
	entry->ipv4_dslite.dmac_lo = swab16(*((u16 *)&neigh->ha[4]));
	entry->ipv4_dslite.smac_hi = swab32(*((u32 *)out->dev_addr));
	entry->ipv4_dslite.smac_lo = swab16(*((u16 *)&out->dev_addr[4]));

	return 0;
}

int mtk_464xlat_get_hash(struct sk_buff *skb, u32 *hash, bool l2w)
{
	struct in6_addr addr_v6, prefix;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	struct tcpudphdr *pptr, _ports;
	struct foe_entry tmp;
	u32 addr, protoff;

	if (l2w) {
		ip6h = ipv6_hdr(skb);
		if (mtk_ppe_get_xlat_v4_by_v6(&ip6h->daddr, &addr))
			return -1;
		protoff = IPV6_HDR_LEN;

		tmp.bfib1.pkt_type = IPV4_HNAPT;
		tmp.ipv4_hnapt.sip = ntohl(ip6h->saddr.s6_addr32[3]);
		tmp.ipv4_hnapt.dip = ntohl(addr);
	} else {
		iph = ip_hdr(skb);
		if (mtk_ppe_get_xlat_v6_by_v4(&iph->saddr, &addr_v6, &prefix))
			return -1;

		protoff = iph->ihl * 4;

		tmp.bfib1.pkt_type = IPV6_5T_ROUTE;
		tmp.ipv6_5t_route.ipv6_sip0 = ntohl(addr_v6.s6_addr32[0]);
		tmp.ipv6_5t_route.ipv6_sip1 = ntohl(addr_v6.s6_addr32[1]);
		tmp.ipv6_5t_route.ipv6_sip2 = ntohl(addr_v6.s6_addr32[2]);
		tmp.ipv6_5t_route.ipv6_sip3 = ntohl(addr_v6.s6_addr32[3]);
		tmp.ipv6_5t_route.ipv6_dip0 = ntohl(prefix.s6_addr32[0]);
		tmp.ipv6_5t_route.ipv6_dip1 = ntohl(prefix.s6_addr32[1]);
		tmp.ipv6_5t_route.ipv6_dip2 = ntohl(prefix.s6_addr32[2]);
		tmp.ipv6_5t_route.ipv6_dip3 = ntohl(iph->daddr);
	}

	pptr = skb_header_pointer(skb, protoff,
				  sizeof(_ports), &_ports);
	if (unlikely(!pptr))
		return -1;

	if (l2w) {
		tmp.ipv4_hnapt.sport = ntohs(pptr->src);
		tmp.ipv4_hnapt.dport = ntohs(pptr->dst);
	} else {
		tmp.ipv6_5t_route.sport = ntohs(pptr->src);
		tmp.ipv6_5t_route.dport = ntohs(pptr->dst);
	}

	*hash = hnat_get_ppe_hash(&tmp);

	return 0;
}

void mtk_464xlat_fill_info1(struct foe_entry *entry,
			    struct sk_buff *skb, bool l2w)
{
	entry->bfib1.cah = 1;
	entry->bfib1.ttl = 1;
	entry->bfib1.state = BIND;
	entry->bfib1.time_stamp = readl(hnat_priv->fe_base + 0x0010) & (0xFF);
	if (l2w) {
		entry->bfib1.pkt_type = IPV4_DSLITE;
		entry->bfib1.udp = ipv6_hdr(skb)->nexthdr ==
				   IPPROTO_UDP ? 1 : 0;
	} else {
		entry->bfib1.pkt_type = IPV6_6RD;
		entry->bfib1.udp = ip_hdr(skb)->protocol ==
				   IPPROTO_UDP ? 1 : 0;
	}
}

void mtk_464xlat_fill_info2(struct foe_entry *entry, bool l2w)
{
	entry->ipv4_dslite.iblk2.mibf = 1;
	entry->ipv4_dslite.iblk2.port_ag = 0xF;

	if (l2w)
		entry->ipv4_dslite.iblk2.dp = NR_GMAC2_PORT;
	else
		entry->ipv6_6rd.iblk2.dp = NR_GMAC1_PORT;
}

void mtk_464xlat_fill_ipv4(struct foe_entry *entry, struct sk_buff *skb,
			   struct foe_entry *foe, bool l2w)
{
	struct iphdr *iph;

	if (l2w) {
		entry->ipv4_dslite.sip = foe->ipv4_dslite.sip;
		entry->ipv4_dslite.dip = foe->ipv4_dslite.dip;
		entry->ipv4_dslite.sport = foe->ipv4_dslite.sport;
		entry->ipv4_dslite.dport = foe->ipv4_dslite.dport;
	} else {
		iph = ip_hdr(skb);
		entry->ipv6_6rd.tunnel_sipv4 = ntohl(iph->saddr);
		entry->ipv6_6rd.tunnel_dipv4 = ntohl(iph->daddr);
		entry->ipv6_6rd.sport = foe->ipv6_6rd.sport;
		entry->ipv6_6rd.dport = foe->ipv6_6rd.dport;
		entry->ipv6_6rd.hdr_chksum = ppe_get_chkbase(iph);
		entry->ipv6_6rd.ttl = iph->ttl;
		entry->ipv6_6rd.dscp = iph->tos;
		entry->ipv6_6rd.flag = ntohs(iph->frag_off) >> 13;
	}
}

int mtk_464xlat_fill_ipv6(struct foe_entry *entry, struct sk_buff *skb,
			  struct foe_entry *foe, bool l2w)
{
	struct ipv6hdr *ip6h;
	struct in6_addr addr_v6, prefix;
	u32 addr;

	if (l2w) {
		ip6h = ipv6_hdr(skb);

		if (mtk_ppe_get_xlat_v4_by_v6(&ip6h->daddr, &addr))
			return -1;

		if (mtk_ppe_get_xlat_v6_by_v4(&addr, &addr_v6, &prefix))
			return -1;

		entry->ipv4_dslite.tunnel_sipv6_0 =
			ntohl(prefix.s6_addr32[0]);
		entry->ipv4_dslite.tunnel_sipv6_1 =
			ntohl(ip6h->saddr.s6_addr32[1]);
		entry->ipv4_dslite.tunnel_sipv6_2 =
			ntohl(ip6h->saddr.s6_addr32[2]);
		entry->ipv4_dslite.tunnel_sipv6_3 =
			ntohl(ip6h->saddr.s6_addr32[3]);
		entry->ipv4_dslite.tunnel_dipv6_0 =
			ntohl(ip6h->daddr.s6_addr32[0]);
		entry->ipv4_dslite.tunnel_dipv6_1 =
			ntohl(ip6h->daddr.s6_addr32[1]);
		entry->ipv4_dslite.tunnel_dipv6_2 =
			ntohl(ip6h->daddr.s6_addr32[2]);
		entry->ipv4_dslite.tunnel_dipv6_3 =
			ntohl(ip6h->daddr.s6_addr32[3]);

		ppe_fill_flow_lbl(entry, ip6h);
		entry->ipv4_dslite.priority = ip6h->priority;
		entry->ipv4_dslite.hop_limit = ip6h->hop_limit;

	} else {
		entry->ipv6_6rd.ipv6_sip0 = foe->ipv6_6rd.ipv6_sip0;
		entry->ipv6_6rd.ipv6_sip1 = foe->ipv6_6rd.ipv6_sip1;
		entry->ipv6_6rd.ipv6_sip2 = foe->ipv6_6rd.ipv6_sip2;
		entry->ipv6_6rd.ipv6_sip3 = foe->ipv6_6rd.ipv6_sip3;
		entry->ipv6_6rd.ipv6_dip0 = foe->ipv6_6rd.ipv6_dip0;
		entry->ipv6_6rd.ipv6_dip1 = foe->ipv6_6rd.ipv6_dip1;
		entry->ipv6_6rd.ipv6_dip2 = foe->ipv6_6rd.ipv6_dip2;
		entry->ipv6_6rd.ipv6_dip3 = foe->ipv6_6rd.ipv6_dip3;
	}

	return 0;
}

int mtk_464xlat_fill_l2(struct foe_entry *entry, struct sk_buff *skb,
			const struct net_device *dev, bool l2w)
{
	const unsigned int *port_reg;
	int port_index;
	u16 sp_tag;

	if (l2w)
		entry->ipv4_dslite.etype = ETH_P_IP;
	else {
		if (IS_DSA_LAN(dev)) {
			port_reg = of_get_property(dev->dev.of_node,
						   "reg", NULL);
			if (unlikely(!port_reg))
				return -1;

			port_index = be32_to_cpup(port_reg);
			sp_tag = BIT(port_index);

			entry->bfib1.vlan_layer = 1;
			entry->bfib1.vpm = 0;
			entry->ipv6_6rd.etype = sp_tag;
		} else
			entry->ipv6_6rd.etype = ETH_P_IPV6;
	}

	if (mtk_464xlat_fill_mac(entry, skb, dev, l2w))
		return -1;

	return 0;
}


int mtk_464xlat_fill_l3(struct foe_entry *entry, struct sk_buff *skb,
			struct foe_entry *foe, bool l2w)
{
	mtk_464xlat_fill_ipv4(entry, skb, foe, l2w);

	if (mtk_464xlat_fill_ipv6(entry, skb, foe, l2w))
		return -1;

	return 0;
}

int mtk_464xlat_post_process(struct sk_buff *skb, const struct net_device *out)
{
	struct foe_entry *foe, entry = {};
	u32 hash;
	bool l2w;

	if (skb->protocol == htons(ETH_P_IPV6))
		l2w = true;
	else if (skb->protocol == htons(ETH_P_IP))
		l2w = false;
	else
		return -1;

	if (mtk_464xlat_get_hash(skb, &hash, l2w))
		return -1;

	if (hash >= hnat_priv->foe_etry_num)
		return -1;

	if (headroom[hash].crsn != HIT_UNBIND_RATE_REACH)
		return -1;

	foe = &hnat_priv->foe_table_cpu[headroom_ppe(headroom[hash])][hash];

	mtk_464xlat_fill_info1(&entry, skb, l2w);

	if (mtk_464xlat_fill_l3(&entry, skb, foe, l2w))
		return -1;

	mtk_464xlat_fill_info2(&entry, l2w);

	if (mtk_464xlat_fill_l2(&entry, skb, out, l2w))
		return -1;

	/* We must ensure all info has been updated before set to hw */
	wmb();
	memcpy(foe, &entry, sizeof(struct foe_entry));

	return 0;
}

static unsigned int mtk_hnat_nf_post_routing(
	struct sk_buff *skb, const struct net_device *out,
	unsigned int (*fn)(struct sk_buff *, const struct net_device *,
			   //struct flow_offload_hw_path *),
			   struct hnat_hw_path *),
	const char *func)
{
	struct foe_entry *entry;
	/*struct flow_offload_hw_path hw_path = { .dev = (struct net_device*)out,
						.virt_dev = (struct net_device*)out };*/
	struct hnat_hw_path hw_path = { .real_dev = out, .virt_dev = out };
	const struct net_device *arp_dev = out;

	if (skb->protocol == htons(ETH_P_IPV6) && !hnat_priv->ipv6_en) {
		return 0;
	}

	if (xlat_toggle && !mtk_464xlat_post_process(skb, out))
		return 0;

	if (skb_hnat_alg(skb) || unlikely(!is_magic_tag_valid(skb) ||
					  !IS_SPACE_AVAILABLE_HEAD(skb)))
		return 0;

	if (unlikely(!skb_mac_header_was_set(skb)))
		return 0;

	if (unlikely(!skb_hnat_is_hashed(skb)))
		return 0;

	/*if (out->netdev_ops->ndo_flow_offload_check) {
		out->netdev_ops->ndo_flow_offload_check(&hw_path);
		out = (IS_GMAC1_MODE) ? hw_path.virt_dev : hw_path.dev;*/
	if (out->netdev_ops->ndo_hnat_check) {
		if (out->netdev_ops->ndo_hnat_check(&hw_path))
			return 0;
		out = (IS_GMAC1_MODE) ? hw_path.virt_dev : hw_path.real_dev;
	}

	if (!IS_LAN_GRP(out) && !IS_WAN(out) && !IS_EXT(out))
		return 0;

	trace_printk("[%s] case hit, %x-->%s, reason=%x\n", __func__,
		     skb_hnat_iface(skb), out->name, skb_hnat_reason(skb));

	if (skb_hnat_entry(skb) >= hnat_priv->foe_etry_num ||
	    skb_hnat_ppe(skb) >= CFG_PPE_NUM)
		return -1;

	entry = &hnat_priv->foe_table_cpu[skb_hnat_ppe(skb)][skb_hnat_entry(skb)];

	switch (skb_hnat_reason(skb)) {
	case HIT_UNBIND_RATE_REACH:
		if (entry_hnat_is_bound(entry))
			break;

		if (fn && !mtk_hnat_accel_type(skb))
			break;

		if (fn && fn(skb, arp_dev, &hw_path))
			break;

		//skb_to_hnat_info(skb, out, entry, &hw_path);
		break;
	case HIT_BIND_KEEPALIVE_DUP_OLD_HDR:
		/* update hnat count to nf_conntrack by keepalive */
		if (hnat_priv->data->per_flow_accounting && hnat_priv->nf_stat_en)
			mtk_hnat_nf_update(skb);

		if (fn && !mtk_hnat_accel_type(skb))
			break;

		/* update dscp for qos */
		mtk_hnat_dscp_update(skb, entry);

		/* update mcast timestamp*/
		if (hnat_priv->data->version == MTK_HNAT_V1_3 &&
		    hnat_priv->data->mcast && entry->bfib1.sta == 1)
			entry->ipv4_hnapt.m_timestamp = foe_timestamp(hnat_priv);

		if (entry_hnat_is_bound(entry)) {
			//memset(skb_hnat_info(skb), 0, sizeof(struct hnat_desc));
			memset(skb_hnat_info(skb), 0, FOE_INFO_LEN);

			return -1;
		}
		break;
	case HIT_BIND_MULTICAST_TO_CPU:
	case HIT_BIND_MULTICAST_TO_GMAC_CPU:
		/*do not forward to gdma again,if ppe already done it*/
		if (IS_LAN_GRP(out) || IS_WAN(out))
			return -1;
		break;
	}

	return 0;
}

static unsigned int
mtk_pong_hqos_handler(void *priv, struct sk_buff *skb,
		      const struct nf_hook_state *state)
{
	mtk_hnat_nf_post_routing(skb, state->out, 0, __func__);
	return NF_ACCEPT;
}

static unsigned int mtk_hnat_br_nf_forward(void *priv,
					   struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
#if !(defined(CONFIG_MEDIATEK_NETSYS_V2) || defined(CONFIG_MEDIATEK_NETSYS_V3))
	//if ((hnat_priv->data->version == MTK_HNAT_V1_2) &&
	if (unlikely(IS_EXT(state->in) && IS_EXT(state->out)))
		if (is_magic_tag_valid(skb) &&
		    likely(skb_headroom(skb) >= FOE_INFO_LEN + ETH_HLEN))
			skb_hnat_alg(skb) = 1;
#endif

	return NF_ACCEPT;
}

static struct nf_hook_ops mtk_hnat_nf_ops[] __read_mostly = {
	{
		.hook = mtk_pong_hqos_handler,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_PRE_ROUTING,
		.priority = NF_BR_PRI_FIRST + 1,
	},
};

int hnat_register_nf_hooks(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0))
	return nf_register_hooks(mtk_hnat_nf_ops, ARRAY_SIZE(mtk_hnat_nf_ops));
#else
	return nf_register_net_hooks(&init_net, mtk_hnat_nf_ops, ARRAY_SIZE(mtk_hnat_nf_ops));
#endif
}

void hnat_unregister_nf_hooks(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0))
	nf_unregister_hooks(mtk_hnat_nf_ops, ARRAY_SIZE(mtk_hnat_nf_ops));
#else
	nf_unregister_net_hooks(&init_net, mtk_hnat_nf_ops, ARRAY_SIZE(mtk_hnat_nf_ops));
#endif
}

int whnat_adjust_nf_hooks(void)
{
	struct nf_hook_ops *hook = mtk_hnat_nf_ops;
	size_t n = ARRAY_SIZE(mtk_hnat_nf_ops);

	for (; n-- > 0;) {
		if (hook[n].hook == mtk_pong_hqos_handler) {
			hook[n].hook = mtk_hnat_br_nf_forward;
			hook[n].hooknum = NF_BR_FORWARD;
			hook[n].priority = NF_BR_PRI_LAST - 1;
		}
	}

	return 0;
}
