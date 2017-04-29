#ifndef _NETLINK_MSG_H
#define _NETLINK_MSG_H


#define IFNAMSIZ 16


enum
{
  WORK_MODE_HIJACK = 1,
  WORK_MODE_DEFAULT
};

enum
{
  OUT_DEVICE = 1,	/* packet received from out device */
  IN_DEVICE		/* packet received from in device */
};

#define OKM_NETLINK	21


#define MSG_TEST_DATA		0x1000
#define MSG_TEST_ACK		0x1100

/* the last bit the netlink type used to stand for the operation results */
/* user -> kernel, tell the information about user application */
#define MSG_HAND_SYN		0x0100	
/* kernel -> user, ack the previous message */
#define MSG_HAND_ACK		0x0200
/* user -> kernel, schedule IP packet */
#define MSG_PKT_SCHEDULE	0x0300
/* kernel -> user, return the real packet tx time */
#define MSG_PKT_SCHEDULE_ACK	0x1300
/* kernel -> user, transmit the pkt received in kernle module */
#define MSG_PKT_RECEIVED	0x0400  
/* kernel <-> user, ack the previous packet message */
#define MSG_PKT_ACK		0x0500
/* user -> kernel, request the information about kernel module */
#define MSG_REQ_KER_INFO	0x0600
/* kernel -> user, request the information about app module */
#define MSG_REQ_APP_INFO	0x0700
/* kernel <-> user, ack the information request message */
#define MSG_REQ_ACK		0x0800
/* user -> kernel, add filter rules to the kernel module */
#define MSG_RULE_ADD		0x0900
/* user -> kernel, del filter rules from the kernel module */
#define MSG_RULE_DEL		0x0A00
/* user -> kernel, lookup the filter rules in the kernel module */
#define MSG_RULE_LOOKUP		0x0B00
/* kernel -> user, return the rules operation results */
#define MSG_RULE_ACK		0x0C00

#define MSG_IDLE		0x0000
#define MSG_HAND_FIN		0x0F00


struct tuple5
{
  unsigned int sip;
  unsigned int dip;
  unsigned short sport;
  unsigned short dport;
  unsigned char protocol;
};

struct rule_append
{
  unsigned int  offset;
  unsigned int  flag;
};

struct msg_pkt_info
{
  int len;
  int protocol;
  int seq;
  unsigned int rule_id;
  unsigned int dev;
  struct timeval tv_rx;
};

struct msg_ip_schedule
{
  int   len;			/* ip packet length */
  int   protocol;		/* protocol */
  int   seq;
  int 	num;
  unsigned int pkt_id;
  unsigned int rule_id;
  unsigned int dev;
  struct timeval tv_delay;	/* delay time */
};


struct msg_hand_syn
{
  char in_dev_name[IFNAMSIZ];	/* name of ethernet conected to the internet */
  char ex_dev_name[IFNAMSIZ];	/* name of ethernet conected to internal network */
  int  work_mode;		/* the mode the kernel mode work on */
};

struct msg_hand_ack
{
  unsigned int in_dev;
  unsigned int ex_dev;
};

struct msg_rule
{
  unsigned int id;
  struct tuple5 tuple;
  struct rule_append apd;
};

struct msg_rule_id
{
  unsigned int id;
};




#define MAX_PAYLOAD 2048

#endif
