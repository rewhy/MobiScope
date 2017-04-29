// nlksp.h

#ifndef _NETLINK_KERNEL_SPACE_H
#define _NETLINK_KERNEL_SPACE_H

#include "nlmsg.h"
#include "pkthijack.h"

int nl_data_snd(int pid, const char *buf, uint32_t buf_len, uint16_t type);
int nl_pkt_to_app(unsigned int id, int pid, const char *pkt, int pktlen, struct timeval tv, struct hijack_device *hidev);
int init_nl_comm(void);
int exit_nl_comm(void);

#endif