// pktrx.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/time.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <net/tcp.h>


#include "pkttx.h"
#include "pktrx.h"
#include "debug.h"
#include "pkthijack.h"
#include "nlksp.h"
#include "rulelist.h"


/* structure netfilter uses register hook function */
static struct nf_hook_ops rx_hook_op;
// static struct nf_hook_ops tx_hook_op;
// static struct nf_hook_ops tx_hook_op1;
// extern struct pkt_hijack_info *phinfo;
// extern struct pkt_hijack_info *plist;


extern struct timeval last_tx_tv;
static unsigned int dip;
static bool isHooking = false;
//unsigned short dport = inet_addr("");

static unsigned int krx_skb_process(struct sk_buff *skb)
{
	struct sk_buff *sb = skb;
	//struct ethhdr *eth = NULL;
	struct iphdr *piph = NULL;
	struct tcphdr *ptcph = NULL;
	struct udphdr *pudph = NULL;
	struct icmphdr *icmph = NULL;
	//struct hijack_device *hdev = NULL;
	struct timeval ts, tx_ts;
	s64 tx_tv, rx_tv, dur;
	static s64 s = 0, e = 0;
	struct tuple5 tuple;
	unsigned char *data = NULL, *tmp = NULL;
	int seq = 0;//, i = 0;
	static int datalen = 0, txnum = 0, rxnum = 0;
	int rule_id;
	int iplen;

	//TRACE_ENTRY;

	/* get the timestamp from the sk_buff and store it in ts */
	skb_get_timestamp(skb, &ts);
	//printk(KERN_INFO "rx_tv = %ld:%ld - %ld:%ld\n", ts.tv_sec, ts.tv_usec, last_tx_tv.tv_sec, last_tx_tv.tv_usec);
	rx_tv = timeval_to_ns(&ts);

	/* get the header from sk_buf */
	piph = ip_hdr(sb);

	//if(piph->saddr != dip)
	//	return 1;

	/* length of ip packet */
	iplen = skb->len;

	if(piph->protocol == IPPROTO_ICMP) { // ICMP packets
		//printk(KERN_INFO "ICMP packet\n");
		tx_ts = *((struct timeval*)((unsigned char *)piph + sizeof(struct iphdr) + sizeof(struct icmphdr)));
		icmph = (struct icmphdr *)((unsigned char *)piph + sizeof(struct iphdr));
		if(icmph->type != ICMP_ECHOREPLY)
			return 1;
		//printk(KERN_INFO "tx_tv = %ld:%ld\n", tx_ts.tv_sec, tx_ts.tv_usec);
		tx_tv = timeval_to_ns(&tx_ts);
		dur = rx_tv - tx_tv;
		ts = ns_to_timeval(dur);
		rx_packet_wake(skb->len, ts, (unsigned char*)piph);
		//printk(KERN_INFO "rtt = %lld ns\n", dur);
		return 0;//rx_packet_wake(skb->len, ts, piph);
	}
	else
	{
		//  return NF_ACCEPT;
		//if(krx_rule_num() == 0)
			//return NF_ACCEPT;
		if(piph->protocol == IPPROTO_UDP) { // UDP packets
			/* for testing */
			tmp = (unsigned char *)piph;
			pudph = (struct udphdr *)(piph + 1);
			data = (unsigned char *)(pudph + 1);
			//printk(KERN_INFO "%x %x %x %x %x %x %x %x %x %x\n",*data, tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[20], tmp[21], tmp[22]);
		
			if(*data == WORK_TYPE_BAND)
			{
				data++;
				seq = *((int *)data);
				if(datalen == 0)
				{
					s = ktime_to_ns(ktime_now());
				}
				if(seq < 0)
				{
					dur = e - s;
					ts = ns_to_timeval(dur);
					*(int *)data = datalen;
					data += sizeof(int);
					*(int *)data = rxnum;
					data += sizeof(int);
					*(int *)data = txnum;
					rx_packet_wake(skb->len, ts, (unsigned char*)piph);
					s = 0;
					e = 0;
					rxnum = 0;
					txnum = 0;
					datalen = 0;
					seq = 0;
					return 0;
				}
				e = ktime_to_ns(ktime_now());
				printk(KERN_INFO "band udp %d\n", seq);
				txnum = seq > txnum ? seq : txnum;
				rxnum++;
				datalen += iplen;
				return 0;
			}
			tuple.sip = piph->saddr;
			tuple.dip = piph->daddr;
			tuple.dport = pudph->dest;
			tuple.sport = pudph->source;
			tuple.protocol = piph->protocol;
			rule_id = krx_rule_lookup(&tuple);

			if(rule_id >= 0) {
				rx_packet_wake(skb->len, ts, (unsigned char*)piph);
			}
		}
		/* if the packet is tcp packet and it's lengh is enough */
		else
		{
			if((piph->protocol == IPPROTO_TCP)) { // TCP packets
				/* tcp header */
				ptcph = (struct tcphdr *)(skb->data + (piph->ihl << 2));
				tuple.sip = piph->saddr;
				tuple.dip = piph->daddr;
				tuple.dport = ptcph->dest;
				tuple.sport = ptcph->source;
				tuple.protocol = piph->protocol;

				//  printk("received tcp packet %d (%d)\n", test++, ptcph->syn);
				/* if the tcp packet is the first hand packet */
				/*if(ptcph->syn  && ptcph->ack_seq == 0 && (skb->len >= (piph->ihl << 2) + (ptcph->doff << 2))) {
					rule_id = krx_rule_add(&tuple, NULL);
					rx_packet_wake(skb->len, ts, piph);
					}
					else {
					rule_id = krx_rule_lookup(&tuple);

					if(rule_id >= 0) {
					rx_packet_wake(skb->len, ts, piph);
				// }
				}*/
				rule_id = krx_rule_lookup(&tuple);

				if(rule_id >= 0) {
					rx_packet_wake(skb->len, ts, (unsigned char*)piph);
				}
			}
		}
	}
	return 1;
}
/*
 * hook function to deal with the packets going through NF_IP_PRE_ROUTING point
 */
unsigned int krx_hook_func(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int(*okfn)(struct sk_buff *))
{
	//TRACE_ENTRY;
	if(krx_skb_process(skb)>0)
		return NF_ACCEPT;
	else
		return NF_DROP;
}



static void nf_hook_register(struct nf_hook_ops *reg)
{
	struct nf_hook_ops *elem;
	list_for_each_entry(elem, &nf_hooks[reg->pf][reg->hooknum], list)
	{
		break;
	}
	list_add_rcu(&reg->list, elem->list.prev);
#if defined(CONFIG_JUMP_LABEL)
	static_key_slow_inc(&nf_hooks_needed[reg->pf][reg->hooknum]);
	// jump_label_inc(&nf_hooks_needed[reg->pf][reg->hooknum]);
#endif
}


static void nf_hook_unregister(struct nf_hook_ops *reg)
{
	list_del_rcu(&reg->list);
#if defined(CONFIG_JUMP_LABEL)
	static_key_slow_dec(&nf_hooks_needed[reg->pf][reg->hooknum]);
	//jump_label_dec(&nf_hooks_needed[reg->pf][reg->hooknum]);
#endif
	synchronize_net();
}
//static struct nf_hook_ops *reg;
/*
 * initialize the hook point and register the hook function at
 * NF_IP_PRE_ROUTING point
 */
int init_nf_pktrx(void)
{
	// TRACE_ENTRY;
	if(isHooking)
		return 0;
	rx_hook_op.hook	= krx_hook_func;
	rx_hook_op.hooknum	= NF_INET_PRE_ROUTING;
	rx_hook_op.pf	= PF_INET;
	rx_hook_op.priority	= NF_IP_PRI_FIRST;
	//nf_register_hook(&rx_hook_op);
	nf_hook_register(&rx_hook_op);
	isHooking = true;
	/* tx_hook_op.hook    = krx_hook_func;
		 tx_hook_op.hooknum = NF_INET_POST_ROUTING;
		 tx_hook_op.pf	= PF_INET;
		 tx_hook_op.priority= NF_IP_PRI_FIRST;
		 tx_hook_op1 = tx_hook_op;
		 nf_register_hook(&tx_hook_op1);*/
	/* endable network device to log packet's timestamp */
	net_enable_timestamp();
	dip = inet_addr("192.168.42.129");

	//TRACE_EXIT;
	return 0;
}

/*
 * unregister the packet hook function
 * exit the packet hijack
 */

int exit_nf_pktrx(void)
{
	//TRACE_ENTRY;
	if(!isHooking)
		return 0;
	//nf_unregister_hook(&rx_hook_op);
	nf_hook_unregister(&rx_hook_op);
	/* disable network device to log packet's timestamp */
	net_disable_timestamp();
	isHooking = false;
	//TRACE_EXIT;
	return 1;
}
