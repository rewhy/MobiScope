// pkttx.h

#ifndef _PACKET_TX_H
#define _PACKET_TX_H

#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
//#include <sys/types.h>

#include "pkthijack.h"


struct pkt_tx_work
{
  struct timer_list *tx_timer;
  struct sk_buff *skb;
  char *pkt;
  unsigned int status;
  unsigned int gap;
  unsigned int seq;
  unsigned int pkt_left;
  unsigned int pkt_len;
  struct timeval eq_tv;
//  struct hijack_device *dev;
  unsigned char rmac[ETH_ALEN];
  struct net_device *d;
};

struct tx_work
{
	unsigned int	work_type;
  unsigned int	pkt_left;
  u64		delay;
  ktime_t	next_tx;
  unsigned char *ip_data;
  unsigned int  len;
  unsigned int  is_running;
  struct net_device *d;
  unsigned char dmac[ETH_ALEN];
  unsigned char smac[ETH_ALEN];
};

struct pkt_schedule
{
  int   len;			/* ip packet length */
  int   protocol;		/* protocol */
  int 	num;
  char  ex_dev_name[IFNAMSIZ];	/* name of ethernet conected to internal network */

	unsigned int work_type;
  struct timeval tx_start;
  struct timeval tv_delay;	/* delay time */
};

int xmit_init(struct pkt_hijack_info *phinfo, char *oeth, char *ieth);
void xmit_exit(void);
void xmit_test(struct pkt_hijack_info *phinfo);
int nl_pkt_schedule(struct pkt_hijack_info *phinfo, char *msg, int len);
//void xmit_tx_test(int, int, int);
int xmit_ip_packet(struct hijack_device *dev,int seq, u_char *ipkt, int pkt_len, struct timeval *delay);
int xmit_pkt_train(struct hijack_device *hidev,int seq, u_char *ipkt, int pkt_len, int num, struct timeval *gap);

int ktx_xmit(struct tx_work *sch);

#endif
