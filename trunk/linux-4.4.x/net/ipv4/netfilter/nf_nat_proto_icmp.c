/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#include <linux/netfilter.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_l4proto.h>

static bool
icmp_in_range(const struct nf_conntrack_tuple *tuple,
	      enum nf_nat_manip_type maniptype,
	      const struct nf_nat_range *range)
{
	const union nf_conntrack_man_proto *min = &range->min_proto;
	const union nf_conntrack_man_proto *max = &range->max_proto;

	if (range->flags & NF_NAT_RANGE_PROTO_PSID) {
		unsigned int a = range->min_proto.psid.offset;
		unsigned int k = range->min_proto.psid.length;
		unsigned int m = 16 - a - k;
		u_int16_t psid = range->max_proto.psid.id;
		u_int16_t id = ntohs(tuple->src.u.icmp.id);

		return (a == 0 || (id >> (16 - a))) &&
		       !(((id >> m) ^ psid) & ~(~0U << k));
	}

	return ntohs(tuple->src.u.icmp.id) >= ntohs(min->icmp.id) &&
	       ntohs(tuple->src.u.icmp.id) <= ntohs(max->icmp.id);
}

static void
icmp_unique_tuple(const struct nf_nat_l3proto *l3proto,
		  struct nf_conntrack_tuple *tuple,
		  const struct nf_nat_range *range,
		  enum nf_nat_manip_type maniptype,
		  const struct nf_conn *ct)
{
	static u_int16_t id;
	unsigned int range_size;
	unsigned int i;

	if (range->flags & NF_NAT_RANGE_PROTO_PSID) {
		unsigned int a = range->min_proto.psid.offset;
		unsigned int k = range->min_proto.psid.length;
		unsigned int m = 16 - a - k;
		u_int16_t psid = range->max_proto.psid.id << m;

		range_size = (1 << (16 - k)) - (!!a << m);
		if (range_size == 0)
			return;

		for (i = 0; ; ++id) {
			unsigned int n = id % range_size;
			tuple->src.u.icmp.id = htons((((n >> m) + !!a) << (16 - a)) |
						     psid | (n & ~(~0U << m)));
			if (++i >= range_size || !nf_nat_used_tuple(tuple, ct))
				return;
		}
		return;
	};

	range_size = ntohs(range->max_proto.icmp.id) -
		     ntohs(range->min_proto.icmp.id) + 1;
	/* If no range specified... */
	if (!(range->flags & NF_NAT_RANGE_PROTO_SPECIFIED))
		range_size = 0xFFFF;

	for (i = 0; ; ++id) {
		tuple->src.u.icmp.id = htons(ntohs(range->min_proto.icmp.id) +
					     (id % range_size));
		if (++i == range_size || !nf_nat_used_tuple(tuple, ct))
			return;
	}
	return;
}

static bool
icmp_manip_pkt(struct sk_buff *skb,
	       const struct nf_nat_l3proto *l3proto,
	       unsigned int iphdroff, unsigned int hdroff,
	       const struct nf_conntrack_tuple *tuple,
	       enum nf_nat_manip_type maniptype)
{
	struct icmphdr *hdr;

	if (!skb_make_writable(skb, hdroff + sizeof(*hdr)))
		return false;

	hdr = (struct icmphdr *)(skb->data + hdroff);
	inet_proto_csum_replace2(&hdr->checksum, skb,
				 hdr->un.echo.id, tuple->src.u.icmp.id, false);
	hdr->un.echo.id = tuple->src.u.icmp.id;
	return true;
}

const struct nf_nat_l4proto nf_nat_l4proto_icmp = {
	.l4proto		= IPPROTO_ICMP,
	.manip_pkt		= icmp_manip_pkt,
	.in_range		= icmp_in_range,
	.unique_tuple		= icmp_unique_tuple,
#if IS_ENABLED(CONFIG_NF_CT_NETLINK)
	.nlattr_to_range	= nf_nat_l4proto_nlattr_to_range,
#endif
};
