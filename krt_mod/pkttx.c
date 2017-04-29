// pkttx.c


#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/time.h>
#include <linux/workqueue.h>
#include <linux/inet.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/freezer.h>
#include <linux/proc_fs.h>

#include "pkthijack.h"
#include "pkttx.h"
#include "debug.h"
#include "nlmsg.h"
#include "log.h"


#define HARD_XMIT_ADDR	0xc0853374

// struct timeval last_tx_tv;

extern int tx_pkts;

//static struct log_info *tx_log = NULL;
extern int is_wait_exit;


unsigned int sum_works = 0;
static  int try_times = 0;
static  int is_running = 0;

//static int dbg_is_first = 0;
//static int dbg_is_last = 0;
//u_char dest_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
//u_char dest_mac[ETH_ALEN] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
//u_char dest_mac[ETH_ALEN] = {0x0c, 0x84, 0xdc, 0xb2, 0x6f, 0xd1}; // jeremy-XPS-8700 wlan0
u_char dest_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
int xmit_init(struct pkt_hijack_info *phinfo, char *oeth, char *ieth)
{
	//TRACE_ENTRY;
	phinfo->exter_dev = kmalloc(sizeof(struct hijack_device), GFP_KERNEL);

	if(!phinfo->exter_dev) {
		printk(KERN_ERR "Malloc external hijack device structure failure\n");
		return -1;
	}

	memset((void *)phinfo->exter_dev, 0, sizeof(struct hijack_device));
	memcpy(phinfo->exter_dev->eth, oeth, IFNAMSIZ);
	memcpy(phinfo->exter_dev->remote_mac, dest_mac, ETH_ALEN);
	phinfo->exter_dev->dev = dev_get_by_name(&init_net, oeth);

	if(phinfo->exter_dev->dev)
		dev_put(phinfo->exter_dev->dev);
	else {
		printk(KERN_ERR "Init external device %s failure\n", oeth);
		kfree(phinfo->exter_dev);
		phinfo->exter_dev = NULL;
		return -1;
	}

	if(phinfo->mode == WORK_MODE_HIJACK) {
		phinfo->inter_dev = kmalloc(sizeof(struct hijack_device), GFP_KERNEL);

		if(!phinfo->inter_dev) {
			printk(KERN_ERR "Malloc internal hijack device structure failure\n");
			kfree(phinfo->exter_dev);
			phinfo->exter_dev = NULL;
			return -1;
		}

		memset(phinfo->inter_dev, 0, sizeof(struct hijack_device));

		if(ieth == NULL)
			return -1;

		memcpy(phinfo->inter_dev->eth, ieth, IFNAMSIZ);
		memcpy(phinfo->inter_dev->remote_mac, dest_mac, ETH_ALEN);
		phinfo->exter_dev->dev = dev_get_by_name(&init_net, ieth);

		if(phinfo->exter_dev->dev)
			dev_put(phinfo->exter_dev->dev);
		else {
			printk(KERN_ERR "Init internal device %s failure\n", ieth);
			kfree(phinfo->exter_dev);
			phinfo->exter_dev = NULL;
			kfree(phinfo->inter_dev);
			phinfo->inter_dev = NULL;
			return -1;
		}
	}

	TRACE_EXIT;
	return 0;
}

void xmit_exit(void)
{
	TRACE_ENTRY;

	is_running = 0;
	//while(phinfo->exter_dev->ptx_works > 0)
	while(sum_works > 0) {
		printk(KERN_INFO "There are still works in external timer queue!\n");
		msleep(200);
	}

	/*  if(phinfo->inter_dev)
			{
			while(phinfo->inter_dev->ptx_works > 0)
			{
			printk(KERN_INFO "There are still works in internal timer queue!\n");
			msleep(200);
			}
			}*/
	TRACE_EXIT;
}
uint16_t csum(u_char *addr, int count)
{
	/* Compute Internet Checksum for "count" bytes
	 *         beginning at location "addr".
	 */
	register long sum = 0;

	while(count > 1)  {
		/*  This is the inner loop */
		sum += *((unsigned short *)addr);
		addr += 2;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if(count > 0)
		sum += *(unsigned char *) addr;

	/*  Fold 32-bit sum to 16 bits */
	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

struct psd_header {
	unsigned long saddr; // sip
	unsigned long daddr; // dip
	u_char mbz;// 0
	u_char ptcl; // protocol
	unsigned short tcpl; //TCP lenth

};

uint16_t tcp_csum(uint32_t saddr, uint32_t daddr, u_char *tcppkt, uint16_t len, unsigned char proto)
{
	u_char buf[1600], *pkt;
	uint16_t rst;
	struct psd_header *psdh;
	int count = sizeof(struct psd_header) + len;
	memset(buf, 0, count);
	psdh = (struct psd_header *)buf;
	pkt = buf + sizeof(struct psd_header);
	psdh->saddr = saddr;
	psdh->daddr = daddr;
	psdh->mbz = 0;
	psdh->ptcl = proto; //IPPROTO_TCP;
	psdh->tcpl = htons(len);
	memcpy(pkt, tcppkt, len);
	rst = csum(buf, count);
	return rst;
}

static void spin(struct tx_work *tx_worker)
{
	ktime_t start_time, end_time;
	s64 remaining;
	struct hrtimer_sleeper t;

	hrtimer_init_on_stack(&t.timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	hrtimer_set_expires(&t.timer, tx_worker->next_tx);

	remaining = ktime_to_ns(hrtimer_expires_remaining(&t.timer));

	if(remaining <= 0) {
		tx_worker->next_tx = ktime_add_ns(tx_worker->next_tx, tx_worker->delay);
		return;
	}

	// printk("Left time %llu ns (%llu, %llu)\n", remaining, ktime_now(), tx_worker->next_tx);
	start_time = ktime_now();

	// for small delay
	if(remaining < 100000) {
		do {
			end_time = ktime_now();
		}
		while(ktime_lt(end_time, tx_worker->next_tx));
	}
	else {
		hrtimer_init_sleeper(&t, current);

		do {
			set_current_state(TASK_INTERRUPTIBLE);
			hrtimer_start_expires(&t.timer, HRTIMER_MODE_ABS);

			if(!hrtimer_active(&t.timer))
				t.task = NULL;

			if(t.task)
				schedule();

			hrtimer_cancel(&t.timer);
			//printk("%lld\n", ktime_now());
		}
		while(t.task && !signal_pending(current));

		__set_current_state(TASK_RUNNING);
		end_time = ktime_now();
	}
	//printk("%lld\n", end_time);
	//printk("%lld %lld %lld %lld %lld\n",start_time, end_time,  ktime_now(), tx_worker->next_tx, remaining);
	//printk("%lld %lld %lld %lld %lld\n\n",start_time, end_time,  ktime_now(), tx_worker->next_tx, remaining);
	tx_worker->next_tx = ktime_add_ns(tx_worker->next_tx, tx_worker->delay);
	//return end_time;
}


static struct sk_buff *tx_construct_skb(struct net_device *dev, unsigned int index, u_char *ipkt, int pkt_len) {
	struct sk_buff *skb = NULL;
	struct ethhdr *ethdr = NULL;
	//struct tcphdr  *tcph = (struct tcphdr *)(ipkt + sizeof(struct iphdr));
	u_char *pdata = NULL;
	int hhlen = LL_RESERVED_SPACE(dev);
	//tcph->dest = htons(index + 1);
	//TRACE_ENTRY;
	skb = alloc_skb(pkt_len + hhlen, GFP_ATOMIC);

	if(!skb) {
		printk(KERN_ERR "xmit: malloc skb failure\n");
		return NULL;
	}

	prefetchw(skb->data);
	skb_reserve(skb, hhlen);

	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = __constant_htons(ETH_P_IP);
	skb->ip_summed = CHECKSUM_NONE;
	skb->priority = 0;

	pdata = skb_put(skb, pkt_len);

	if(ipkt)
		memcpy(pdata, ipkt, pkt_len);

	skb_set_network_header(skb, 0); // skb->network_header = skb->data + 0
	skb_set_transport_header(skb, sizeof(struct iphdr));// skb->transport_header = skb->data + sizeof(struct iphdr)

	ethdr = (struct ethhdr *)skb_push(skb, 14);

	skb->dev = dev;
	memcpy(ethdr->h_source, dev->dev_addr, ETH_ALEN);

	memcpy(ethdr->h_dest, dest_mac, ETH_ALEN);

	ethdr->h_proto = __constant_htons(ETH_P_IP);
	//  TRACE_EXIT;
	return skb;
}


static int tx_queue_skb(struct sk_buff *skb)
{

	printk(KERN_INFO "send packet\n");
	if(dev_queue_xmit(skb) < 0) {
		printk(KERN_ERR "dev_queue_xmit transmit sk_buff failure");
		kfree_skb(skb);
		return NET_XMIT_DROP;
	}
	else
		return NETDEV_TX_OK;
}

/* refer to dev_hard_xmit() */
static int tx_skb1(struct sk_buff *skb)
{
	int ret = -1;
	u16 queue_map = 2;
	struct netdev_queue *txq;
	struct net_device *odev = skb->dev;
	int (*krt_hard_start_xmit)(struct sk_buff *skb, struct net_device *dev, struct netdev_queue *txq);
	krt_hard_start_xmit = HARD_XMIT_ADDR;
	rcu_read_lock_bh();
	queue_map = skb_get_queue_mapping(skb);
	txq = netdev_get_tx_queue(odev, queue_map);
	if(odev->flags & IFF_UP){
		int cpu = smp_processor_id();
		if(txq->xmit_lock_owner != cpu) {
			HARD_TX_LOCK(odev, txq, cpu);
			printk(KERN_INFO "pkttx");
			//ret = krt_hard_start_xmit(skb, odev, txq);
			HARD_TX_UNLOCK(odev, txq);
		}
	}
	if(net_ratelimit()) {
		printk(KERN_CRIT "Virtual device %s asks to queue packet!\n", odev->name);
	}
	if(skb && ret != NETDEV_TX_OK)
		kfree_skb(skb);
	rcu_read_unlock_bh();
	return ret;
}

/* refer to pktgen_xmit() */
static int tx_skb2(struct sk_buff *skb)
{
	int ret;
	u16 queue_map = 2;
	struct netdev_queue *txq;
	struct net_device *odev = skb->dev;
	queue_map = skb_get_queue_mapping(skb);
	txq = netdev_get_tx_queue(odev, queue_map);
	printk("queue_map = %d\n", queue_map);

	try_times = 0;

	is_running = 1;

	do {
		__netif_tx_lock_bh(txq);
		// netif_tx_queue_frozen_or_stopped
		// netif_tx_queue_frozen
		// netif_xmit_frozen_or_stopped
		// if(unlikely(netif_tx_queue_frozen(txq))) {
		// if(unlikely(netif_tx_queue_frozen_or_stopped(txq))) {
		if(unlikely(netif_xmit_frozen_or_stopped(txq))) {
			ret = NETDEV_TX_BUSY;
			try_times++;
		}
		else {
			atomic_inc(&(skb->users));
			ret = odev->netdev_ops->ndo_start_xmit(skb, odev);
			//ret = krt_hard_start_xmit(skb, odev, txq);
			switch(ret) {
				case NETDEV_TX_OK:
					txq_trans_update(txq);
					//printk("xmit ok.\n" , ret);
					break;
				case NET_XMIT_DROP:
				case NET_XMIT_CN:
				case NET_XMIT_POLICED:
					printk("dropped (%d).\n" , ret);
					break;
				case NETDEV_TX_LOCKED:
				case NETDEV_TX_BUSY:
					printk("locked of busy (%d).\n", ret);
					atomic_dec(&(skb->users));
					try_times++;
					break;
				default:
					if(net_ratelimit()) {
						printk("xmit error: %d\n", ret);
					}
					printk("default result.\n");
					atomic_dec(&(skb->users));
					break;
			}
		}
		__netif_tx_unlock_bh(txq);
		cpu_relax();
		try_to_freeze();

		if(ret == NETDEV_TX_BUSY && try_times < 10)
			schedule();
	}	while((ret == NETDEV_TX_BUSY || ret == NETDEV_TX_LOCKED) && is_running);

	if(skb)
		kfree_skb(skb);
	return ret;
}
/* refer to pktgen_xmit() */
static int tx_skb(struct sk_buff *skb)
{
		int ret;
		u16 queue_map = 2;
		struct netdev_queue *txq;
		struct net_device *odev = skb->dev;
		int (*krt_hard_start_xmit)(struct sk_buff *skb, struct net_device *dev, struct netdev_queue *txq);
		krt_hard_start_xmit = HARD_XMIT_ADDR;//0xc06b3edc;
		queue_map = skb_get_queue_mapping(skb);
		txq = netdev_get_tx_queue(odev, queue_map);
		// printk("queue_map = %d\n", queue_map);

		try_times = 0;

		is_running = 1;

		do {
			__netif_tx_lock_bh(txq);
			if(unlikely(netif_xmit_frozen_or_stopped(txq))) {
				ret = NETDEV_TX_BUSY;
				try_times++;
			}
			else {
				ret = krt_hard_start_xmit(skb, odev, txq);
				switch(ret) {
					case NETDEV_TX_OK:
						txq_trans_update(txq);
						//printk("xmit ok\n");
						break;
					default:
						if(net_ratelimit()) {
							printk("xmit error: %d\n", ret);
						}
						printk("default result.\n");
						break;
				}
			}
			__netif_tx_unlock_bh(txq);
			cpu_relax();
			try_to_freeze();

			if(ret == NETDEV_TX_BUSY && try_times < 10)
				schedule();
		}
		while((ret == NETDEV_TX_BUSY || ret == NETDEV_TX_LOCKED) && is_running);

		if(skb && ret)
			kfree_skb(skb);

		return ret;
	}


	int ktx_xmit(struct tx_work *tw)
	{
		struct sk_buff *skb = NULL;
		struct sk_buff *test[101];
		int r = 0, i = 0, j = 0;
		int cycle = 0;
		int pktlen = 0;
		static int ttt = 0;
		struct timeval *d = NULL;
		struct iphdr *iph = NULL;
		struct icmphdr *icmph = NULL;
		struct udphdr *udph = NULL;
		unsigned char *data = NULL;
		int datalen = 0;
		bool isTx = false;
		ktime_t s, e;
		s64 nstart = 0, nnow = 0, txdur = 0;
		//TRACE_ENTRY;  /* tx as fast as possible */
		printk("type: %d  %d pkts will be tx with time gap  %d\n", tw->work_type, tw->pkt_left, tw->delay);

		if(tw->work_type == WORK_TYPE_PING) {
			//printk("%d pkts will be tx with time gap  %lld\n", tw->pkt_left, tw->delay);
			d = (struct timeval *)(tw->ip_data + sizeof(struct iphdr) + sizeof(struct icmphdr));
			do_gettimeofday(d);
			//printk(KERN_INFO "tx: %ld.%ld\n", d->tv_sec, d->tv_usec);
			//pktlen = sizeof(struct icmphdr) + datalen;
			pktlen = tw->len - sizeof(struct iphdr);
			//printk(KERN_INFO "pktlen=%d (%d %d)\n", pktlen, sizeof(struct iphdr), sizeof(struct icmphdr));
			icmph = (struct icmphdr *)(tw->ip_data + sizeof(struct iphdr));
			icmph->checksum = 0;
			icmph->checksum = csum((unsigned char *)icmph, pktlen);
			skb = tx_construct_skb(tw->d, 1, tw->ip_data, tw->len);
			tx_skb(skb);
			return 0;
		}
		else if(tw->work_type == WORK_TYPE_BAND) {
			iph = (struct iphdr *)tw->ip_data;
			udph = (struct udphdr *)(tw->ip_data + sizeof(struct iphdr));
			data = (unsigned char *)udph + sizeof(struct udphdr);
			pktlen = tw->len - sizeof(struct iphdr);
			isTx = true;
			txdur = tw->delay;
			printk(KERN_INFO "pktlen = %d, tsdur = %lld\n", pktlen, txdur);
			*data = (unsigned char)WORK_TYPE_BAND;
			data++;
			s = ktime_now();
			nstart = ktime_to_ns(s);
			do{
				e = ktime_now();
				nnow = ktime_to_ns(e);
				if(nnow - nstart > txdur)
				{
					*((unsigned int*)data) = (0 - ++i);
					isTx = false;
				}
				else
				{
					*((unsigned int*)data) = ++i;
				}
				udph->check = 0;
				udph->check = tcp_csum(iph->saddr, iph->daddr, (unsigned char*)udph, pktlen, IPPROTO_UDP);
				datalen += tw->len;
				if(!isTx)
				{
					msleep(20);
				}
				skb = tx_construct_skb(tw->d, 1, tw->ip_data, tw->len);
				tx_queue_skb(skb);
			}while(isTx);
			return i;
		}
		s = ktime_now();

		if(tw->delay == 0 && tw->pkt_left > 1 && tw->pkt_left <= 101) {
			ttt = 0;
			for(i = 0; i < tw->pkt_left; i++) {
				test[i] = tx_construct_skb(tw->d, i, tw->ip_data, tw->len);

				if(!test[i]) {
					printk(KERN_ERR "%s(%d): construct skb error.\n", __func__, __LINE__);
					break;
				}
			}

			for(j = 0; j < i - 1; j++) {
				r = tx_queue_skb(test[j]);

				if(r == NETDEV_TX_OK)
					tw->pkt_left--;
				else
					printk(KERN_ERR "%s(%d): (%d pkts left (%d)) tx packet error.\n", __func__, __LINE__, tw->pkt_left, ttt++);
			}

			r = tx_skb(test[j]);

			if(r == NETDEV_TX_OK)
				tw->pkt_left--;
			else
				printk(KERN_ERR "%s(%d):tx packet error.\n", __func__, __LINE__);

			j++;
		}
		else {

			if(tw->delay > NSEC_PER_SEC) {
				cycle = tw->delay - NSEC_PER_SEC;
				tw->delay = 0;
			}

			tw->next_tx = ktime_now();
			i = tw->pkt_left;

			for(j = 0; j < i -1; j++) {
				skb = tx_construct_skb(tw->d, j, tw->ip_data, tw->len);

				if(!skb) {
					printk(KERN_ERR "%s(%d): construct skb error (left %d skbs).\n", __func__, __LINE__, tw->pkt_left);
					break;
				}


				if(cycle > 0) {
					tw->delay = (cycle * j) % (cycle * 5);
				}

				if(tw->delay > 0) {
					spin(tw);

					//t=ktime_now();
					//printk("%lld %lld\n", t, tw->next_tx);

					//printk("%lld  %lld\n",t, ktime_now());
					r = tx_skb(skb);

				}
				else {
					r = tx_queue_skb(skb);
					//r = tx_skb(skb);
				}

				if(r == NETDEV_TX_OK) {
					tw->pkt_left--;
				}
				else {
					printk("Error: %d left packets (tried %d times).\n", tw->pkt_left, try_times);
				}
			}

			skb = tx_construct_skb(tw->d, j, tw->ip_data, tw->len);

			if(tw->delay > 0)
				spin(tw);

			r = tx_skb(skb);

			if(r == NETDEV_TX_OK) {
				tw->pkt_left--;
			}
			else
			{
				printk("%s(%d):skb tx error.\n", __func__, __LINE__);
			}
			j++;
		}

		e = ktime_now();
		printk("tx: %d (left %d ) pkts duration: %lld (%lld - %lld)\n", j, tw->pkt_left, e.tv64 - s.tv64, e.tv64, s.tv64);
		return tw->pkt_left;
	}

