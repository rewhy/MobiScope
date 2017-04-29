// rulelist.c

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/mutex.h>

#include "pkthijack.h"
#include "hash.h"
#include "rulelist.h"
#include "debug.h"


extern struct pkt_hijack_info *phinfo;

static struct rulelist *krx_flist = NULL;


//static struct rule_node **rule_table = NULL;
static int rules_num = 0;
//static rwlock_t list_lock;
//static unsigned int seq = 0; // rule's identification
static int rules_table_size = 256; // hash table's size
//static int max_rules = 1024; // max length of rules
static unsigned dip;


// print the tuple information used for debug
void tuple_print(struct tuple5 *t, int pkts, char *info)
{
  char source[16], dest[16];
  inet_ntoa(t->sip, source);
  inet_ntoa(t->dip, dest);
  MYDBG("%s(%d %d): %s:%d ---> %s:%d (%d)\n", info, rules_num,  pkts, source, ntohs(t->sport), dest, ntohs(t->dport), t->protocol);
  MYDBG("%u:%u -> %u:%u %u\n", t->sip, t->sport, t->dip, t->dport, t->protocol);
  
}



int krx_rule_num(void)
{
  if(krx_flist)
    return krx_flist->rules_num;
  else
    return 0;
}
/* 
 * initialize the filter rules list
 * malloc hash table memmory and initialize the hash table
 */
int krx_rule_init(void)
{
  return 0;
  krx_flist = rule_list_init();
  if(!krx_flist)
    return 1;
  else
    return 0;
}
struct rulelist* rule_list_init(void)
{
  //TRACE_ENTRY;
  struct rulelist *rule_list = kmalloc(sizeof(struct rulelist), GFP_ATOMIC);
  if(rule_list == NULL)
    return NULL;
  memset(rule_list, 0, sizeof(struct rulelist));
  rule_list->seq = 0;
  rwlock_init(&rule_list->list_lock);
  rule_list->rule_table = (struct rule_node **)kmalloc(rules_table_size * sizeof(struct rule_node *), GFP_ATOMIC);
  if(rule_list->rule_table == NULL)
  {
    printk("malloc rule table error..");
    kfree(rule_list);
    return NULL;
  }
  //MYDBG("RULE LIST: %X\n", (int)rule_list);
  memset((void *)rule_list->rule_table, 0, rules_table_size * sizeof(struct rule_node *));
  //MYDBG("RULE TABLE: %X\n", (int)rule_list->rule_table);
  TRACE_EXIT;
  return rule_list;
}

/*
 * compute the hash index of the tuple5
 */
static uint32_t mk_hash_index(struct tuple5 *tup)
{
  int hash = mkhash(tup->sip, tup->sport, tup->dip, tup->dport);
  return hash % rules_table_size;
}

/*
 * add new rule to the rules list
 */
int krx_rule_add(struct tuple5 *tup, struct rule_append *apd)
{
  return 0;
  dip = tup->sip;
  return rule_add(krx_flist, tup, apd);
}
int rule_add(struct rulelist *rule_list, struct tuple5 *tup, struct rule_append *apd)
{
//  TRACE_ENTRY;
 
  struct rule_node *t = NULL;
  struct rule_node *tmp = kmalloc(sizeof(struct rule_node), GFP_ATOMIC);
  int index = mk_hash_index(tup);
  // printk("hash: %d\n", index);
  
  if(!tmp)
  {
    printk("Malloc rule node failure\n");
    return -1;
  }
  memset((void *)tmp, 0, sizeof(struct rule_node));
  tmp->id = rule_list->seq;
  rule_list->seq++;
  tmp->pkts = 1;
  if(tup)
  {
    tmp->tuple.dip = tup->dip;// > 0? tup->dip : ~0x00000000;
    tmp->tuple.sip = tup->sip;// > 0? tup->sip : ~0x00000000;
    tmp->tuple.dport = tup->dport;// > 0 ? tup->dport : ~0x0000;
    tmp->tuple.sport = tup->sport;// > 0 ? tup->sport : ~0x0000;
    tmp->tuple.protocol = tup->protocol;// > 0 ? tup->protocol : ~0x00;
  }

  if(apd)
  {
    tmp->apd.offset = apd->offset;
    tmp->apd.flag = apd->flag;
  }
  t = rule_list->rule_table[index];
  
  write_lock(&rule_list->list_lock);
  
  if(t == NULL)
    rule_list->rule_table[index] = tmp;
  else
  {
    while(t->next)
      t = t->next;
    t->next = tmp;
    tmp->prev = t;
  }
  rule_list->rules_num++;
  write_unlock(&rule_list->list_lock);
  //printk("%d ", index );
  tuple_print(tup, tmp->id, "Add");
  return tmp->id;
}

/*
 * lookup the match rule in list according to the tuple5
 */
static int rule_match(const struct tuple5 *tup, struct rule_node *rnode)
{
  struct tuple5 *tmp = &rnode->tuple;
//  tuple_print(tup, 0, "tupe");
//  tuple_print(tmp, 0, "rule");  
/*  if((tmp->protocol > 0) && (tup->protocol != tmp->protocol))
  {
    return 0;
  }*/
  
  if(tmp->sip == tup->sip)
  {
    printk("%u:%u --> %u:%u  %u\n", tmp->sip, htons(tmp->sport), tmp->dip, htons(tmp->dport), tmp->protocol);
    printk("%u:%u --> %u:%u  %u\n", tup->sip, htons(tup->sport), tup->dip, htons(tup->dport), tup->protocol);
  }
  if((tmp->sip > 0) && (tup->sip != tmp->sip))
  {
//    printk("sip: %x %x %x %x\n", tup->sip,tmp->sip, ~tmp->sip, tup->sip & ~tmp->sip);
    return 0;
  }
  
  if((tmp->dip > 0) && (tup->dip != tmp->dip))
  {
//    printk("dip: %d %d %d\n", tup->dip, tmp->dip, tmp->dip & ~tmp->dip);
    return 0;
  }
  
  if((tmp->sport > 0) &&(tup->sport != tmp->sport))
  {
 //   printk("sport: %d %d %d\n", tup->sport, tmp->sport, tup->sport & ~tmp->sport);
    return 0;
  }
  
  if((tmp->dport > 0) && (tup->dport != tmp->dport))
  {
//    printk("dport: %d %d %d\n", tup->dport, tmp->dport, tup->dport & ~tmp->dport);
    return 0; 
  }

  return 1;
}

/*
 * delete the filter rule according to the rule's ID 
 */
int rule_del_by_id(struct rulelist *rule_list, char *data, int len)
{
  struct msg_rule *msg;
  struct rule_node *tmp;// = rule_list_head;
  unsigned int id;
  
  int i;
 // TRACE_ENTRY;
  if(len < sizeof(struct msg_rule))
  {
    printk(KERN_ERR "Del message is too short\n");
    return -1;
  }  
  msg = (struct msg_rule *)data;
  id = msg->id;
  if(rule_list->rules_num < 1)
    return 0;
  write_lock(&rule_list->list_lock);   
  for(i=0; i < rules_table_size; i++)
  {
    tmp = rule_list->rule_table[i];
    while(tmp)
    {
      if(tmp->id == id)
      {
	break;	
      }
      tmp = tmp->next;      
    }
    if(tmp)
    {
      if(tmp->prev)
	tmp->prev->next = tmp->next;
      else
	rule_list->rule_table[i] = tmp->next;
      if(tmp->next)
	tmp->next->prev = tmp->prev;
      kfree(tmp);
      rule_list->rules_num--;
      break;
    }
  }
  write_unlock(&rule_list->list_lock);
  return  rule_list->rules_num;
  
}

int krx_rule_lookup(struct tuple5 *tuple)
{
  struct rule_node *tmp = NULL;
  int index;
  if(tuple->dip == dip || tuple->sip == dip)
    return 1;
  else
    return -1;
  
  if(krx_flist->rules_num < 1)
    return -1;  
  index = mk_hash_index(tuple);
  
  read_lock(&krx_flist->list_lock);
  tmp = krx_flist->rule_table[index];
  while(tmp)
  {
    if(rule_match(tuple, tmp) > 0)
    {
      break;
    }
    tmp = tmp->next;
  }
  read_unlock(&krx_flist->list_lock);
  if(tmp)
  {
    tmp->pkts++;
    return tmp->id;
  }
  else
    return -1;
}

/* 
 *lookup the rules list  according to the ip header
 */
int rule_lookup(struct rulelist *rule_list, struct iphdr *iph)
{
  struct rule_node *tmp = NULL;
  struct tuple5 tuple;
  struct tcphdr *tcph;
  int index;
  
  if(rule_list->rules_num < 1)
    return -1;
  tuple.sip = iph->saddr;
  tuple.dip = iph->daddr;
  tuple.protocol = iph->protocol;
  
  tcph = (struct tcphdr *)(((char *)iph) + (iph->ihl << 2));
  tuple.sport = tcph->source;
  tuple.dport = tcph->dest;
  
  index = mk_hash_index(&tuple);
  
  read_lock(&rule_list->list_lock);
  tmp = rule_list->rule_table[index];
  while(tmp)
  {
    if(rule_match(&tuple, tmp) > 0)
    {
      /*  if(htons(tuple.sport) == 80)
	{
	  tuple_print(&tuple, 1, "PKT");
	  tuple_print(&tmp->tuple, 1, "RUL");
	}*/
      break;
    }
    tmp = tmp->next;
  }
  read_unlock(&rule_list->list_lock);
  if(tmp)
  {
    tmp->pkts++;
    return tmp->id;
  }
  else
    return -1;
}

/*
 * clear all the rules
 */
int krx_rule_clr()
{
  return 0;
  return rule_clr(krx_flist);
}
int rule_clr(struct rulelist *rule_list)
{
  struct rule_node *next, *tmp;
  int i;
  TRACE_ENTRY;
  if(rule_list == NULL || rule_list->rule_table == NULL)
  {
    MYDBG("%p  %x\n", rule_list, (int)rule_list->rule_table);
    return -1;
  }

 // write_lock(&rule_list->list_lock);
  MYDBG("There are %d rules left\n", rule_list->rules_num);
  for(i = 0; i < rules_table_size; i++)
  {
    tmp = rule_list->rule_table[i]; 
    while(tmp)
    {	
      next = tmp->next;
      kfree(tmp);
      tmp = next;
      rule_list->rules_num--;      
    } 
  }
  MYDBG("%d\n", rule_list->rules_num );
  if(rule_list->rules_num != 0)
  {
    MYDBG("Error (left %d) !!!\n", rule_list->rules_num);
  }
  else
  {
    MYDBG("Perfect !\n");
  }
 // write_unlock(&rule_list->list_lock);
  TRACE_EXIT;
  return 0;
}


/*
 * release the filter rules list 
 */
void krx_rule_list_release()
{
  return;
	TRACE_ENTRY;
  rule_list_release(krx_flist);
	TRACE_EXIT;
}
void rule_list_release(struct rulelist *rule_list)
{
  return;
  if(rule_list == NULL)
    return;
  rule_clr(rule_list); 
  if(rule_list->rule_table)
    kfree((void *)rule_list->rule_table);
  kfree((void *)rule_list);
}
