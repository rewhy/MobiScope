// nlksp.c

/* netlink's kernel module */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/time.h>
#include <linux/ip.h>


#include "debug.h"
#include "nlksp.h"
#include "pkthijack.h"
#include "pkttx.h"
#include "nlmsg.h"
#include "pktrx.h"
#include "rulelist.h"
// #include "log.h"

static struct sock *nl_sk = NULL;
//static uint32_t pid;

//struct pkt_hijack_info *phinfo;
extern rwlock_t list_hijack_lock;
extern struct pkt_hijack_info *plist;
extern int process_num;
/* process the information received from application layer */
int del_process(unsigned int pid)
{
  struct pkt_hijack_info *pre = NULL, *tmp = NULL;
  write_lock(&list_hijack_lock);
  tmp = plist;
  while(tmp)
  {
    if(tmp->usr_pid == pid)
      break;
    else
    {
      pre = tmp;
      tmp=tmp->next;
    }
  }
  if(tmp == NULL)
    return -1;
  if(pre == NULL)
    plist = tmp->next;
  else
    pre->next = tmp->next;
  write_unlock(&list_hijack_lock);
  //xmit_exit(phinfo);
  process_num--;
  MYDBG("now process num == %d \n", process_num);
  del_hijack_process(tmp);  
	return 0;
}

/* send data to application layer */
int
nl_data_snd(int pid, const char *buf, uint32_t buf_len, uint16_t type)
{
  struct nlmsghdr *send_nlh = NULL;
  struct sk_buff *nl_skb;
  int len = NLMSG_SPACE(buf_len);
  int ret;
  
  nl_skb = alloc_skb(len, GFP_ATOMIC);
  if(!nl_skb)
  {
    printk(KERN_ERR "nel_link: allocate skbuf failed.\n");
    return -1;
  }
  
  send_nlh = nlmsg_put(nl_skb, 0, 0, type, buf_len, 0);

 // NETLINK_CB(nl_skb).pid = 0;
  
  if(nl_sk && pid > 0)
  {
//    printk("dest process ID %d\n", phinfo->usr_pid);
    if(buf)
      memcpy((void *)NLMSG_DATA(send_nlh), buf, buf_len);
    ret = netlink_unicast(nl_sk, nl_skb, pid, MSG_DONTWAIT);
 //   printk("unicast finish! (ret: %d, len: %d, pid: %d)\n", ret, send_nlh->nlmsg_len, phinfo->usr_pid);
 //   return 0;
    if(ret < 0)
    {
      printk(KERN_ERR "netlink: can not unicast skb (ret:%d  pid:%d)\n", ret, pid);
      //exit_nf_pktrx();
      del_process(pid);
      return -1;
    }
//    MYDBGL("send message (0x%4x)", send_nlh->nlmsg_type);
  }
  else
  {
    printk(KERN_ERR "netlink:nor dest process (%d) or created netlink socket", pid);
    return -1;

  }
//  TRACE_EXIT;  
  return 0;
}

int nl_hand_ack(struct pkt_hijack_info *phinfo,int type)
{
  struct msg_hand_ack msg;
  msg.ex_dev = (unsigned int)phinfo->exter_dev;
  if(phinfo->mode == WORK_MODE_HIJACK)
    msg.in_dev = (unsigned int)phinfo->inter_dev;
  nl_data_snd(phinfo->usr_pid, (char *)&msg, sizeof(msg), type);  
	return 0;
}

/* transfer the received tcp packet data to the application module */
int 
nl_pkt_to_app(unsigned int id, int pid, const char *pkt, int pktlen, struct timeval tv, struct hijack_device *hidev)
{
  struct nlmsghdr *nlh = NULL;
  struct sk_buff *nl_skb = NULL;
  struct msg_pkt_info *pmsg;
  struct iphdr *iph = (struct iphdr *)pkt;
  char *data;
  int ret;
  int len = NLMSG_SPACE(pktlen + sizeof(struct msg_pkt_info));
  nl_skb = alloc_skb(len, GFP_ATOMIC);
  
  if(!nl_skb)
  {
    printk(KERN_ERR "%d malloc sk_buff failure\n", __LINE__);
    return -1;
  }
  nlh = nlmsg_put(nl_skb, 0, 0, MSG_PKT_RECEIVED, len - NLMSG_SPACE(0), 0);
  //NETLINK_CB(nl_skb).pid = 0;
  
  
  if(nl_sk && pid > 0)
  {
    pmsg = (struct msg_pkt_info *)NLMSG_DATA(nlh);   
    pmsg->len = pktlen;
    pmsg->seq = hidev->rx_pkts;
    pmsg->dev = (unsigned long)hidev;
    pmsg->rule_id = id;
    pmsg->tv_rx = tv;
    pmsg->protocol = iph->protocol;
    
    data = NLMSG_DATA(nlh) + sizeof(struct msg_pkt_info);
    if(pkt && pktlen > 0)
      memcpy(data, pkt, pktlen);

    ret = netlink_unicast(nl_sk, nl_skb, pid, MSG_DONTWAIT);

 //   return 0;
    if(ret < 0)
    {
      printk(KERN_ERR "netlink: can not unicast skb (%d)\n", ret);
      del_process(pid);
      return -1;
    }
//    MYDBG("Received packet(%d) %d on time %d.%d\n", pktlen, pmsg->seq, tv.tv_sec, tv.tv_usec);
    hidev->rx_pkts++;
 //   MYDBGL("send message (0x%4x)", send_nlh->nlmsg_type);
  }
  else
  {
    printk(KERN_ERR "netlink:nor dest process (%d) or created netlink socket", pid);
    kfree_skb(nl_skb);
    return -1;

  }
//  TRACE_EXIT;  
  return 0;
}


/*static int
nl_rule_add(struct pkt_hijack_info *phinfo, char *data, int len)
{
  struct msg_rule *msg;  
  if(len < sizeof(struct msg_rule))
  {
    printk(KERN_ERR "Del message is too short\n");
    return -1;
  }  
  msg = (struct msg_rule *)data;
  rule_add(phinfo->rule_list, &msg->tuple, NULL);
  return 1;
}*/

/* initialize netlink kernell module for communication */
int 
init_nl_comm(void)
{
  TRACE_ENTRY;
 // phinfo->
  //nl_sk = netlink_kernel_create(&init_net, OKM_NETLINK, 0, nl_data_rcv, NULL, THIS_MODULE);
  if(nl_sk == NULL)
  {
    printk(KERN_ERR "net_link: Create netlink socket failture!\n");
    return -1;
  }
  MYDBG("net_link: Create netlink successfully!\n");
  return 0;
}
/* cleanup netlink kernel module for communication */
int 
exit_nl_comm(void)
{
  TRACE_ENTRY;
  if(nl_sk != NULL)
  {
    sock_release(nl_sk->sk_socket);
  }
  //exit_nf_pktrx();
  TRACE_EXIT;
  return 0;
}
