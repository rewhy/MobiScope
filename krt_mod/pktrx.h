// pktrx.h
#ifndef _PKT_RX_H
#define _PKT_RX_H

struct rx_msg
{
  int len;
  struct timeval ts;
};


int init_nf_pktrx(void);
int exit_nf_pktrx(void );
#endif
