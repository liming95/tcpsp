/*
 * tcpsp_core.c: main management and initialization routines
 *
 * Version:     $Id: tcpsp_core.c,v 1.4 2003/11/11 15:34:23 wensong Exp $
 *
 * Authors:     Wensong Zhang <wensong@linux-vs.org>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Changes:
 *
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#include <linux/config.h>
#endif

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>                   /* for icmp_send */
#include <net/route.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/timex.h>

#include "tcpsp.h"
//#include <net/tcpsp.h>


const char *tcpsp_proto_name(unsigned proto)
{
	static char buf[20];

	switch (proto) {
	case IPPROTO_IP:
		return "IP";
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_ICMP:
		return "ICMP";
	default:
		sprintf(buf, "IP_%d", proto);
		return buf;
	}
}


static void tcpsp_reset_sock(struct sock *sk)
{
	TCPSP_DBG(7, "set sock ECONNRESET\n");
	sk->sk_err = ECONNRESET;
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_error_report(sk);

	tcp_done(sk);
}


/* this function is modified from tcp_parse_option (tcp_input.c) */
static void tcp_parse_timestamps(struct tcphdr *th, __u32 **ts_p)
{
	unsigned char *ptr;
	int length = (th->doff*4) - sizeof(struct tcphdr);

	ptr = (unsigned char *)(th + 1);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2) /* "silly options" */
				return;
			if (opsize > length)
				return;	/* don't parse partial options */
			switch(opcode) {
			case TCPOPT_TIMESTAMP:
				if(opsize == TCPOLEN_TIMESTAMP)
					*ts_p = (__u32 *)ptr;
				break;
			};
			ptr += opsize - 2;
			length -= opsize;
		};
	}
}

/* it only parse timestamp locations*/
static inline int
tcp_fast_parse_timestamps(struct tcphdr *th, __u32 **ts_p)
{
	if (th->doff == sizeof(struct tcphdr)>>2) {
		return 0;
	}

	if (th->doff ==
	    (sizeof(struct tcphdr)>>2)+(TCPOLEN_TSTAMP_ALIGNED>>2)) {
		__u32 *ptr = (__u32 *)(th + 1);
		if (*ptr == __constant_ntohl((TCPOPT_NOP << 24) |
					     (TCPOPT_NOP << 16) |
					     (TCPOPT_TIMESTAMP << 8) |
					     TCPOLEN_TIMESTAMP)) {
			++ptr;
			*ts_p = ptr;
			return 1;
		}
	}

	/* there is a chance that the fast parse doesn't work, then
	   try slow parse for TCP timestamps */
	tcp_parse_timestamps(th, ts_p);

	return 0;
}

/*
 *	Check if it's for tcp splicing connections
 *	and send it on its way...
 */
static unsigned int tcpsp_in(void *priv,
			     struct sk_buff *skb_p,
			     const struct nf_hook_state *state)
{
	struct sk_buff	*skb = skb_p;
	struct iphdr	*iph = ip_hdr(skb);
	struct tcphdr   *th;
	struct tcpsp_conn *cp;
	int ihl, datalen;
	int direction;
	struct conn_tuple *cin, *cout;
	__u32 seq, ack_seq;
	__u32 *ts;
	int rc;
	
	struct timespec64 ts_start, ts_end;
	struct timespec64 ts_delta;
	
	ktime_get_boottime_ts64(&ts_start);
	/* ICMP handling will be considered later */
	/*	if (iph->protocol == IPPROTO_ICMP) */
	/*		return tcpsp_in_icmp(skb_p); */

	/* let it go if other IP protocols */
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	/* make sure that protocol header available in skb data area,
	   note that skb data area may be reallocated. */
	ihl = iph->ihl << 2;
	if (!pskb_may_pull(skb, ihl+sizeof(struct tcphdr)))
		return NF_DROP;
	iph = ip_hdr(skb);
	datalen = skb->len - ihl;
	th = (void *)iph + ihl;

	/*
	 * Check if the packet belongs to an existing connection entry
	 */
	cp = tcpsp_conn_get(iph->saddr, th->source,
			    iph->daddr, th->dest, &direction);

	if (!cp) {
		/* sorry, all this trouble for a no-hit :) */
		TCPSP_DBG(12, "packet for %s %pI4:%d continue "
			  "traversal as normal.\n",
			  tcpsp_proto_name(iph->protocol),
			  &iph->daddr,
			  ntohs(th->dest));
		return NF_ACCEPT;
	}

	/* Add incremental checksum update later? */

	/* full checksum check here now */
	if (skb_is_nonlinear(skb)) {
		if (skb_linearize(skb) != 0) {
			tcpsp_conn_put(cp);
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		th = (void *)iph + ihl;
	}
	switch (skb->ip_summed) {
	case CHECKSUM_NONE:
		skb->csum = csum_partial((void *)th, datalen, 0);
		break;
	case CHECKSUM_COMPLETE:
		if (csum_tcpudp_magic(iph->saddr, iph->daddr,
				      datalen, IPPROTO_TCP, skb->csum)) {
			TCPSP_DBG_RL("Incoming failed checksum "
				     "from %pI4 (datalen=%d)!\n",
				     &iph->saddr, datalen);
			tcpsp_conn_put(cp);
			return NF_DROP;
		}
		break;
	default:/* CHECKSUM_UNNECESSARY */
		break;
	}

	if (th->doff*4 > sizeof(struct tcphdr))
		TCPSP_DBG(7, "there is tcp option: doff %u > %lu\n",
			  th->doff*4, sizeof(struct tcphdr));

	TCPSP_DBG(7, "Incoming %s %pI4:%d->%pI4:%d  "
		  "seq %u ack %u len %d\n",
		  tcpsp_proto_name(iph->protocol),
		  &iph->saddr, ntohs(th->source),
		  &iph->daddr, ntohs(th->dest),
		  ntohl(th->seq), ntohl(th->ack_seq),
		  datalen - th->doff*4);

	tcpsp_set_state(cp, direction, iph, th);

	cin = &cp->conn[direction];
	cout = &cp->conn[!direction];

	/* send first data ack packet from the server to the upper layer */
	if (direction == 1 &&
	    th->ack && datalen - th->doff*4 == 0 &&
	    ntohl(th->seq) == cin->splice_irs &&
	    ntohl(th->ack_seq) <= cin->splice_iss) {
		TCPSP_DBG(7, "ack packet: seq %u==splice_irs %u and "
			  "ack %u<=splice_iss %u, so let it go\n",
			  ntohl(th->seq),cin->splice_irs,
			  ntohl(th->ack_seq), cin->splice_iss);
		tcpsp_conn_put(cp);
		return NF_ACCEPT;
	}

//	if (direction == 1 &&
//	    ntohl(th->seq) == cin->splice_irs &&
//	    ntohl(th->ack_seq) >= cin->splice_iss &&
//	    atomic_dec_and_test(&cp->need_rst)) {
//		TCPSP_DBG(7, "data ack from server: seq %u==splice_irs %u and "
//			  "ack %u==splice_iss %u, then reset socks\n",
//			  ntohl(th->seq),cin->splice_irs,
//			  ntohl(th->ack_seq), cin->splice_iss);
//		tcpsp_reset_sock(cp->socket[0]->sk);
//		tcpsp_reset_sock(cp->socket[1]->sk);
//	}

	/* compute sequences */
	seq = cout->splice_iss + (ntohl(th->seq) - cin->splice_irs);
	ack_seq = cout->splice_irs + (ntohl(th->ack_seq) - cin->splice_iss);

	/* compute timestamps if presented */
	if (cin->timestamp_ok && tcp_fast_parse_timestamps(th, &ts)) {
		__u32 tsval, tsecho;

		tsval = ntohl(ts[0]) - cin->splice_tsv + cout->splice_tse;
		tsecho = ntohl(ts[1]) - cin->splice_tse + cout->splice_tsv;
		TCPSP_DBG (7, "the original cin timestamps:(tsval %u, tsecho %u), cout timestamps:"
			  "(tsval %u, tsecho %u)\n",
			  cin->splice_tsv, cin->splice_tse,
			  cout->splice_tsv, cout->splice_tse);

		TCPSP_DBG (7, "cin timestamps: (tsval %u, tsecho %u), cout timestamps:"
			   "(tsval %u, tsecho %u)\n",
			   ntohl(ts[0]), ntohl(ts[1]),
			   tsval, tsecho);
		ts[0] = htonl(tsval);
		ts[1] = htonl(tsecho);
	}

	TCPSP_DBG(7, "Outgoing %s %pI4:%d->%pI4:%d  seq %u ack %u\n",
		  tcpsp_proto_name(iph->protocol),
		  &cp->conn[!direction].laddr,
		  ntohs(cp->conn[!direction].lport),
		  &cp->conn[!direction].raddr,
		  ntohs(cp->conn[!direction].rport),
		  seq, ack_seq);

	iph->saddr = cout->laddr;
	iph->daddr = cout->raddr;
	th->source = cout->lport;
	th->dest = cout->rport;
	th->seq = htonl(seq);
	th->ack_seq = htonl(ack_seq);
	th->check = 0;
	th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
				      datalen, iph->protocol,
				      csum_partial((char *)th, datalen, 0));
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	ip_send_check(iph);

	if (cp->packet_xmit)
		rc = cp->packet_xmit(skb);
	else
		rc = NF_ACCEPT;

	tcpsp_conn_put(cp);
	ktime_get_boottime_ts64(&ts_end);

	ts_delta = timespec64_sub(ts_end, ts_start);

	printk(KERN_DEBUG"TCPSP: time consumed: %lld (us)\n", timespec64_to_ns(&ts_delta) / 1000);
	return NF_STOLEN;
}


static struct nf_hook_ops tcpsp_in_ops = {
	.hook = tcpsp_in, 
	.pf = PF_INET, 
	.hooknum = NF_INET_LOCAL_IN, 
	.priority = 100
};


static int __init tcpsp_init(void)
{
	int ret;

	ret = tcpsp_control_init();
	if (ret < 0) {
		TCPSP_ERR("can't setup control.\n");
		goto cleanup_nothing;
	}

	ret = tcpsp_conn_init();
	if (ret < 0) {
		TCPSP_ERR("can't setup connection table.\n");
		goto cleanup_control;
	}
	ret = nf_register_net_hook(&init_net, &tcpsp_in_ops);
	if (ret < 0) {
		TCPSP_ERR("can't register in hook.\n");
		goto cleanup_conn;
	}

	TCPSP_INFO("tcpsp loaded.\n");
	return ret;

  cleanup_conn:
	tcpsp_conn_cleanup();
  cleanup_control:
	tcpsp_control_cleanup();
  cleanup_nothing:
	return ret;
}

static void __exit tcpsp_cleanup(void)
{
	nf_unregister_net_hook(&init_net, &tcpsp_in_ops);
	tcpsp_conn_cleanup();
	tcpsp_control_cleanup();
	TCPSP_INFO("tcpsp unloaded.\n");
}

module_init(tcpsp_init);
module_exit(tcpsp_cleanup);
MODULE_LICENSE("GPL");
