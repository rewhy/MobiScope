// hijack.h
#ifndef _PKT_HIJACK_H
#define _PKT_HIJACK_H

#include <linux/types.h>
#include <linux/time.h>
#include "rulelist.h"

#define WORK_TYPE_PING		0x00000001
#define	WORK_TYPE_BAND		0X00000002

struct hijack_device
{
  char eth[IFNAMSIZ];
  struct net_device *dev;
  unsigned char self_mac[ETH_ALEN];
  unsigned char remote_mac[ETH_ALEN];
  unsigned int rx_pkts;
  unsigned int tx_pkts;
  unsigned int ptx_works; /* the left packet tx works */
};

struct pkt_hijack_info
{ 
  struct hijack_device *inter_dev;
  struct hijack_device *exter_dev;   
  struct rulelist *rule_list;		/* point to the rules list */
  u_char		mode; 		/* the mode this moudle is working on */  
  unsigned int usr_pid;			/* the user application process ID */  
  struct pkt_hijack_info *next;
  unsigned char is_tx;
  unsigned char is_rx;
  unsigned char is_end;

	unsigned char hooked;
  
  // for debugging
  struct timeval tv_start;
  struct timeval tv_end;
  unsigned int rx_blen;
  unsigned int rx_pkts;
  
};

void rx_packet_wake(int len, struct timeval ts, unsigned char *data);
struct pkt_hijack_info *new_hijack_process(void);
void del_hijack_process(struct pkt_hijack_info *phino);

ktime_t ktime_now(void);
int ktime_lt(const ktime_t cmpl, const ktime_t cmp2);

unsigned int inet_addr(char* ip);
//char *inet_ntoa(unsigned int in);
char *inet_ntoa(const unsigned int addr, char *buf);

#endif
