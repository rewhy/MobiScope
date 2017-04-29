#ifndef _TESTU_H
#define _TESTU_H

#include <time.h>
#include <stdint.h>

#define WORK_TYPE_PING 0x00000001
#define WORK_TYPE_BAND 0x00000002

typedef struct _measure_info
{
  char eth[16];
  unsigned int sip;
  unsigned int dip;
  unsigned short sport;
  unsigned short dport;
  unsigned int tx_pkts;
  unsigned int rx_pkts;
  unsigned int init_seq;
  unsigned int pkt_num;
  unsigned char protocol;
  unsigned int pkt_len;
  unsigned char is_rx;
  unsigned char is_tx;
  unsigned int cycle;
  unsigned int iterates;
  struct timeval gap;
  struct timeval start_tx;
  struct timeval finish_tx;
  
} measure_info;

// typedef struct _log_rx_pkt
// {
//   struct timeval rx_tv;
//   unsigned int ack;
//   struct _log_rx_pkt *next;
// } log_rx_pkt;

typedef struct _measure_res
{
  unsigned short sport;
  struct timeval tv_tx;
  struct timeval tv_rx;
} measure_res;


struct tuple5
{
  unsigned int sip;
  unsigned int dip;
  unsigned short sport;
  unsigned short dport;
  unsigned char protocol;
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
struct rx_rule_msg
{
  int type;
  struct tuple5 tuple;
};

struct rx_msg
{
  int len;
  struct timeval ts;
};

typedef struct _opt_tcp
{
  uint8_t opt_code;
  uint8_t opt_len;
} opt_tcp;

#endif
