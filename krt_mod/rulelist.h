// rulelist.h

#ifndef _RULE_LIST_H
#define _RULE_LIST_H

#include "nlmsg.h"

struct rx_rule_msg
{
  int type;
  struct tuple5 tuple;
};

struct rulelist
{
  struct rule_node **rule_table;
 // struct rule_node *default_table;
  unsigned int rules_num;
  unsigned int seq;
  rwlock_t list_lock;  
};

struct rule_node
{
  unsigned int id;
  struct tuple5 tuple;
  unsigned int pkts;
  struct rule_append apd;
  struct rule_node *prev;
  struct rule_node *next;
};

struct rulelist* rule_list_init(void);	// initialize the rule list
int rule_clr(struct rulelist *rule_list);	// clear the rule list
int rule_del_by_id(struct rulelist *rule_list, char *data, int len);	// delete rule according to the id
int rule_add(struct rulelist *rule_list, struct tuple5 *tup, struct rule_append *apd); // add new rule to the list
int rule_lookup(struct rulelist *rule_list, struct iphdr *iph);	// lookup matched rule of the ip header.
void rule_list_release(struct rulelist *rule_list);

int krx_rule_init(void);
int krx_rule_num(void);
int krx_rule_clr(void);	// clear the rule list
int krx_rule_add(struct tuple5 *tup, struct rule_append *apd); // add new rule to the list
int krx_rule_lookup(struct tuple5 *tuple);	// lookup matched rule of the ip header.
void krx_rule_list_release(void);

#endif //_RULE_LIST_H
