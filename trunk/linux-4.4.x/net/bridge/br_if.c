/*
 *	Userspace interface
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netpoll.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/if_vlan.h>
#include <net/switchdev.h>

#include "br_private.h"

/*
 * Determine initial path cost based on speed.
 * using recommendations from 802.1d standard
 *
 * Since driver might sleep need to not be holding any locks.
 */
static int port_cost(struct net_device *dev)
{
	struct ethtool_cmd ecmd;

	if (!__ethtool_get_settings(dev, &ecmd)) {
		switch (ethtool_cmd_speed(&ecmd)) {
		case SPEED_10000:
			return 2;
		case SPEED_1000:
			return 4;
		case SPEED_100:
			return 19;
		case SPEED_10:
			return 100;
		}
	}

	/* Old silly heuristics based on name */
	if (!strncmp(dev->name, "lec", 3))
		return 7;

	if (!strncmp(dev->name, "plip", 4))
		return 2500;

	return 100;	/* assume old 10Mbps */
}


/* Check for port carrier transitions. */
void br_port_carrier_check(struct net_bridge_port *p)
{
	struct net_device *dev = p->dev;
	struct net_bridge *br = p->br;

	if (!(p->flags & BR_ADMIN_COST) &&
	    netif_running(dev) && netif_oper_up(dev))
		p->path_cost = port_cost(dev);

	if (!netif_running(br->dev))
		return;

	spin_lock_bh(&br->lock);
	if (netif_running(dev) && netif_oper_up(dev)) {
		if (p->state == BR_STATE_DISABLED)
			br_stp_enable_port(p);
	} else {
		if (p->state != BR_STATE_DISABLED)
			br_stp_disable_port(p);
	}
	spin_unlock_bh(&br->lock);
}

static void br_port_set_promisc(struct net_bridge_port *p)
{
	int err = 0;

	if (br_promisc_port(p))
		return;

	err = dev_set_promiscuity(p->dev, 1);
	if (err)
		return;

	br_fdb_unsync_static(p->br, p);
	p->flags |= BR_PROMISC;
}

static void br_port_clear_promisc(struct net_bridge_port *p)
{
	int err;

	/* Check if the port is already non-promisc or if it doesn't
	 * support UNICAST filtering.  Without unicast filtering support
	 * we'll end up re-enabling promisc mode anyway, so just check for
	 * it here.
	 */
	if (!br_promisc_port(p) || !(p->dev->priv_flags & IFF_UNICAST_FLT))
		return;

	/* Since we'll be clearing the promisc mode, program the port
	 * first so that we don't have interruption in traffic.
	 */
	err = br_fdb_sync_static(p->br, p);
	if (err)
		return;

	dev_set_promiscuity(p->dev, -1);
	p->flags &= ~BR_PROMISC;
}

/* When a port is added or removed or when certain port flags
 * change, this function is called to automatically manage
 * promiscuity setting of all the bridge ports.  We are always called
 * under RTNL so can skip using rcu primitives.
 */
void br_manage_promisc(struct net_bridge *br)
{
	struct net_bridge_port *p;
	bool set_all = false;

	/* If vlan filtering is disabled or bridge interface is placed
	 * into promiscuous mode, place all ports in promiscuous mode.
	 */
	if ((br->dev->flags & IFF_PROMISC) || !br_vlan_enabled(br))
		set_all = true;

	list_for_each_entry(p, &br->port_list, list) {
		if (set_all) {
			br_port_set_promisc(p);
		} else {
			/* If the number of auto-ports is <= 1, then all other
			 * ports will have their output configuration
			 * statically specified through fdbs.  Since ingress
			 * on the auto-port becomes forwarding/egress to other
			 * ports and egress configuration is statically known,
			 * we can say that ingress configuration of the
			 * auto-port is also statically known.
			 * This lets us disable promiscuous mode and write
			 * this config to hw.
			 */
			if (br->auto_cnt == 0 ||
			    (br->auto_cnt == 1 && br_auto_port(p)))
				br_port_clear_promisc(p);
			else
				br_port_set_promisc(p);
		}
	}
}

static void nbp_update_port_count(struct net_bridge *br)
{
	struct net_bridge_port *p;
	u32 cnt = 0;

	list_for_each_entry(p, &br->port_list, list) {
		if (br_auto_port(p))
			cnt++;
	}
	if (br->auto_cnt != cnt) {
		br->auto_cnt = cnt;
		br_manage_promisc(br);
	}
}

static void nbp_delete_promisc(struct net_bridge_port *p)
{
	/* If port is currently promiscuous, unset promiscuity.
	 * Otherwise, it is a static port so remove all addresses
	 * from it.
	 */
	dev_set_allmulti(p->dev, -1);
	if (br_promisc_port(p))
		dev_set_promiscuity(p->dev, -1);
	else
		br_fdb_unsync_static(p->br, p);
}

static void release_nbp(struct kobject *kobj)
{
	struct net_bridge_port *p
		= container_of(kobj, struct net_bridge_port, kobj);
	kfree(p);
}

static struct kobj_type brport_ktype = {
#ifdef CONFIG_SYSFS
	.sysfs_ops = &brport_sysfs_ops,
#endif
	.release = release_nbp,
};

static void destroy_nbp(struct net_bridge_port *p)
{
	struct net_device *dev = p->dev;

	p->br = NULL;
	p->dev = NULL;
	dev_put(dev);

	kobject_put(&p->kobj);
}

static void destroy_nbp_rcu(struct rcu_head *head)
{
	struct net_bridge_port *p =
			container_of(head, struct net_bridge_port, rcu);
	destroy_nbp(p);
}

/* Delete port(interface) from bridge is done in two steps.
 * via RCU. First step, marks device as down. That deletes
 * all the timers and stops new packets from flowing through.
 *
 * Final cleanup doesn't occur until after all CPU's finished
 * processing packets.
 *
 * Protected from multiple admin operations by RTNL mutex
 */
static void del_nbp(struct net_bridge_port *p)
{
	struct net_bridge *br = p->br;
	struct net_device *dev = p->dev;

	sysfs_remove_link(br->ifobj, p->dev->name);

	nbp_delete_promisc(p);

	spin_lock_bh(&br->lock);
	br_stp_disable_port(p);
	spin_unlock_bh(&br->lock);

	br_ifinfo_notify(RTM_DELLINK, p);

	list_del_rcu(&p->list);

	nbp_vlan_flush(p);
	br_fdb_delete_by_port(br, p, 0, 1);
	switchdev_deferred_process();

	nbp_update_port_count(br);

	netdev_upper_dev_unlink(dev, br->dev);

	dev->priv_flags &= ~IFF_BRIDGE_PORT;

	netdev_rx_handler_unregister(dev);

	br_multicast_del_port(p);

	kobject_uevent(&p->kobj, KOBJ_REMOVE);
	kobject_del(&p->kobj);

	br_netpoll_disable(p);

	call_rcu(&p->rcu, destroy_nbp_rcu);
}

/* Delete bridge device */
void br_dev_delete(struct net_device *dev, struct list_head *head)
{
	struct net_bridge *br = netdev_priv(dev);
	struct net_bridge_port *p, *n;

	list_for_each_entry_safe(p, n, &br->port_list, list) {
		del_nbp(p);
	}

	br_fdb_delete_by_port(br, NULL, 0, 1);

	br_vlan_flush(br);
	br_multicast_dev_del(br);
	del_timer_sync(&br->gc_timer);

	br_sysfs_delbr(br->dev);
	unregister_netdevice_queue(br->dev, head);
}

/* find an available port number */
static int find_portno(struct net_bridge *br)
{
	int index;
	struct net_bridge_port *p;
	unsigned long *inuse;

	inuse = kcalloc(BITS_TO_LONGS(BR_MAX_PORTS), sizeof(unsigned long),
			GFP_KERNEL);
	if (!inuse)
		return -ENOMEM;

	set_bit(0, inuse);	/* zero is reserved */
	list_for_each_entry(p, &br->port_list, list) {
		set_bit(p->port_no, inuse);
	}
	index = find_first_zero_bit(inuse, BR_MAX_PORTS);
	kfree(inuse);

	return (index >= BR_MAX_PORTS) ? -EXFULL : index;
}

/* called with RTNL but without bridge lock */
static struct net_bridge_port *new_nbp(struct net_bridge *br,
				       struct net_device *dev)
{
	int index;
	struct net_bridge_port *p;

	index = find_portno(br);
	if (index < 0)
		return ERR_PTR(index);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (p == NULL)
		return ERR_PTR(-ENOMEM);

	p->br = br;
	dev_hold(dev);
	p->dev = dev;
	p->path_cost = port_cost(dev);
	p->priority = 0x8000 >> BR_PORT_BITS;
	p->port_no = index;
	p->flags = BR_LEARNING | BR_FLOOD;
	br_init_port(p);
	br_set_state(p, BR_STATE_DISABLED);
	br_stp_port_timer_init(p);
	br_multicast_add_port(p);

	return p;
}

int br_add_bridge(struct net *net, const char *name)
{
	struct net_device *dev;
	int res;

	dev = alloc_netdev(sizeof(struct net_bridge), name, NET_NAME_UNKNOWN,
			   br_dev_setup);

	if (!dev)
		return -ENOMEM;

	dev_net_set(dev, net);
	dev->rtnl_link_ops = &br_link_ops;

	res = register_netdev(dev);
	if (res)
		free_netdev(dev);
	return res;
}

int br_del_bridge(struct net *net, const char *name)
{
	struct net_device *dev;
	int ret = 0;

	rtnl_lock();
	dev = __dev_get_by_name(net, name);
	if (dev == NULL)
		ret =  -ENXIO; 	/* Could not find device */

	else if (!(dev->priv_flags & IFF_EBRIDGE)) {
		/* Attempt to delete non bridge device! */
		ret = -EPERM;
	}

	else if (dev->flags & IFF_UP) {
		/* Not shutdown yet. */
		ret = -EBUSY;
	}

	else
		br_dev_delete(dev, NULL);

	rtnl_unlock();
	return ret;
}

/* MTU of the bridge pseudo-device: ETH_DATA_LEN or the minimum of the ports */
int br_min_mtu(const struct net_bridge *br)
{
	const struct net_bridge_port *p;
	int mtu = 0;

	ASSERT_RTNL();

	if (list_empty(&br->port_list))
		mtu = ETH_DATA_LEN;
	else {
		list_for_each_entry(p, &br->port_list, list) {
			if (!mtu  || p->dev->mtu < mtu)
				mtu = p->dev->mtu;
		}
	}
	return mtu;
}

/*
 * Recomputes features using slave's features
 */
netdev_features_t br_features_recompute(struct net_bridge *br,
	netdev_features_t features)
{
	struct net_bridge_port *p;
	netdev_features_t mask;

	if (list_empty(&br->port_list))
		return features;

	mask = features;
	features &= ~NETIF_F_ONE_FOR_ALL;

	list_for_each_entry(p, &br->port_list, list) {
		features = netdev_increment_features(features,
						     p->dev->features, mask);
	}
	features = netdev_add_tso_features(features, mask);

	return features;
}

/* called with RTNL */
int br_add_if(struct net_bridge *br, struct net_device *dev)
{
	struct net_bridge_port *p;
	int err = 0;
	bool changed_addr;

	/* Don't allow bridging non-ethernet like devices, or DSA-enabled
	 * master network devices since the bridge layer rx_handler prevents
	 * the DSA fake ethertype handler to be invoked, so we do not strip off
	 * the DSA switch tag protocol header and the bridge layer just return
	 * RX_HANDLER_CONSUMED, stopping RX processing for these frames.
	 */
	if ((dev->flags & IFF_LOOPBACK) ||
	    dev->type != ARPHRD_ETHER || dev->addr_len != ETH_ALEN ||
	    !is_valid_ether_addr(dev->dev_addr) ||
	    netdev_uses_dsa(dev))
		return -EINVAL;

	/* No bridging of bridges */
	if (dev->netdev_ops->ndo_start_xmit == br_dev_xmit)
		return -ELOOP;

	/* Device has master upper dev */
	if (netdev_master_upper_dev_get(dev))
		return -EBUSY;

	/* No bridging devices that dislike that (e.g. wireless) */
	if (dev->priv_flags & IFF_DONT_BRIDGE)
		return -EOPNOTSUPP;

	p = new_nbp(br, dev);
	if (IS_ERR(p))
		return PTR_ERR(p);

	call_netdevice_notifiers(NETDEV_JOIN, dev);

	err = dev_set_allmulti(dev, 1);
	if (err) {
		kfree(p);	/* kobject not yet init'd, manually free */
		goto err1;
	}

	err = kobject_init_and_add(&p->kobj, &brport_ktype, &(dev->dev.kobj),
				   SYSFS_BRIDGE_PORT_ATTR);
	if (err)
		goto err2;

	err = br_sysfs_addif(p);
	if (err)
		goto err2;

	err = br_netpoll_enable(p);
	if (err)
		goto err3;

	err = netdev_rx_handler_register(dev, br_handle_frame, p);
	if (err)
		goto err4;

	dev->priv_flags |= IFF_BRIDGE_PORT;

	err = netdev_master_upper_dev_link(dev, br->dev);
	if (err)
		goto err5;

	dev_disable_lro(dev);

	list_add_rcu(&p->list, &br->port_list);

	nbp_update_port_count(br);

	netdev_update_features(br->dev);

	if (br->dev->needed_headroom < dev->needed_headroom)
		br->dev->needed_headroom = dev->needed_headroom;

	if (br_fdb_insert(br, p, dev->dev_addr, 0))
		netdev_err(dev, "failed insert local address bridge forwarding table\n");

	err = nbp_vlan_init(p);
	if (err) {
		netdev_err(dev, "failed to initialize vlan filtering on this port\n");
		goto err6;
	}

	spin_lock_bh(&br->lock);
	changed_addr = br_stp_recalculate_bridge_id(br);

	if (netif_running(dev) && netif_oper_up(dev) &&
	    (br->dev->flags & IFF_UP))
		br_stp_enable_port(p);
	spin_unlock_bh(&br->lock);

	br_ifinfo_notify(RTM_NEWLINK, p);

	if (changed_addr)
		call_netdevice_notifiers(NETDEV_CHANGEADDR, br->dev);

	dev_set_mtu(br->dev, br_min_mtu(br));

	kobject_uevent(&p->kobj, KOBJ_ADD);

	return 0;

err6:
	list_del_rcu(&p->list);
	br_fdb_delete_by_port(br, p, 0, 1);
	nbp_update_port_count(br);
	netdev_upper_dev_unlink(dev, br->dev);

err5:
	dev->priv_flags &= ~IFF_BRIDGE_PORT;
	netdev_rx_handler_unregister(dev);
err4:
	br_netpoll_disable(p);
err3:
	sysfs_remove_link(br->ifobj, p->dev->name);
err2:
	kobject_put(&p->kobj);
	dev_set_allmulti(dev, -1);
err1:
	dev_put(dev);
	return err;
}

/* called with RTNL */
int br_del_if(struct net_bridge *br, struct net_device *dev)
{
	struct net_bridge_port *p;
	bool changed_addr;

	p = br_port_get_rtnl(dev);
	if (!p || p->br != br)
		return -EINVAL;

	/* Since more than one interface can be attached to a bridge,
	 * there still maybe an alternate path for netconsole to use;
	 * therefore there is no reason for a NETDEV_RELEASE event.
	 */
	del_nbp(p);

	dev_set_mtu(br->dev, br_min_mtu(br));

	spin_lock_bh(&br->lock);
	changed_addr = br_stp_recalculate_bridge_id(br);
	spin_unlock_bh(&br->lock);

	if (changed_addr)
		call_netdevice_notifiers(NETDEV_CHANGEADDR, br->dev);

	netdev_update_features(br->dev);

	return 0;
}

void br_port_flags_change(struct net_bridge_port *p, unsigned long mask)
{
	struct net_bridge *br = p->br;

	if (mask & BR_AUTO_MASK)
		nbp_update_port_count(br);
}

/* Update bridge statistics for bridge packets processed by offload engines */
void br_dev_update_stats(struct net_device *dev,
			 struct rtnl_link_stats64 *nlstats)
{
	struct net_bridge *br;
	struct pcpu_sw_netstats *stats;

	/* Is this a bridge? */
	if (!(dev->priv_flags & IFF_EBRIDGE))
		return;

	br = netdev_priv(dev);
	//stats = per_cpu_ptr(br->stats, 0);
	stats = this_cpu_ptr(br->stats);

	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets += nlstats->rx_packets;
	stats->rx_bytes += nlstats->rx_bytes;
	stats->tx_packets += nlstats->tx_packets;
	stats->tx_bytes += nlstats->tx_bytes;
	u64_stats_update_end(&stats->syncp);
}
EXPORT_SYMBOL_GPL(br_dev_update_stats);
