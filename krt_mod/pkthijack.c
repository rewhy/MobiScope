#include <linux/module.h>       /* Specifically, a module */
#include <linux/kernel.h>       /* We're doing kernel work */
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include<linux/tcp.h>
#include<linux/ip.h>
#include <linux/in.h>
#include <linux/skbuff.h>

#include "pkthijack.h"
#include "debug.h"
#include "pktrx.h"
//#include "nlksp.h"
#include "pkttx.h"
#include "hash.h"
#include "rulelist.h"

int tx_pkts = 0;
rwlock_t list_hijack_lock;
struct pkt_hijack_info *plist = NULL;
int process_num = 0;
int is_wait_exit = 0;
u_char bro_mac[ETH_ALEN] = {0x00, 0x00, 0x0c, 0x07, 0xac, 0x01};//{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
//helper functions
unsigned int inet_addr(char *ip)
{
    int a, b, c, d;
    char addr[4];

    sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d);
    addr[0] = a;
    addr[1] = b;
    addr[2] = c;
    addr[3] = d;

    return *(unsigned int *)addr;
}


char *inet_ntoa(const unsigned int addr, char *buf)
{
    u_char s1 = (addr & 0xFF000000) >> 24;
    u_char s2 = (addr & 0x00FF0000) >> 16;
    u_char s3 = (addr & 0x0000FF00) >> 8;
    u_char s4 = (addr & 0x000000FF);
    sprintf(buf, "%d.%d.%d.%d", s4, s3, s2, s1);
    return buf;
}

ktime_t ktime_now(void)
{
	struct timespec ts;
	ktime_get_ts(&ts);
	//printk("ktime now: %lu.%lu.\n.", ts.tv_sec, ts.tv_nsec);
	return timespec_to_ktime(ts);
}
int ktime_lt(const ktime_t cmpl, const ktime_t cmp2)
{
	return cmpl.tv64 < cmp2.tv64;
}

/* module information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jeremy");
MODULE_DESCRIPTION("OMware Kernel Module");
MODULE_ALIAS("Android Linux Kernel Module");
MODULE_VERSION("0.1");

/* deal with new process from user layer */
struct pkt_hijack_info *new_hijack_process(void) {
    struct pkt_hijack_info *tmp = NULL;
    //TRACE_ENTRY;
    tmp = (struct pkt_hijack_info *)kmalloc(sizeof(struct pkt_hijack_info), GFP_ATOMIC);

    if(tmp == NULL) {
        printk(KERN_ERR "malloc new pkt_hijack_info error...\n");
        return NULL;
    }

    memset((void *)tmp, 0, sizeof(struct pkt_hijack_info));
    tmp->rule_list = rule_list_init();

    if(tmp->rule_list == NULL) {
        kfree(tmp);
        return NULL;
    }

    MYDBG("%x\n", (int)tmp);
    //TRACE_EXIT;
    return tmp;
}

void del_hijack_process(struct pkt_hijack_info *phinfo)
{
    //TRACE_ENTRY;
    // debug info about packet RX
    //double duration, brate, prate;
    int sec, usec;

    sec = phinfo->tv_end.tv_sec - phinfo->tv_start.tv_sec;
    usec = phinfo->tv_end.tv_usec - phinfo->tv_start.tv_usec;

    if(usec < 0) {
        sec -= 1;
        usec += 1000000;
    }

    //duration = (double)sec + ((double)usec/1000000.0);
    //brate = (double)phinfo->rx_blen / duration;
    // prate = (double)phinfo->rx_pkts / duration;

    printk(KERN_INFO "duration: %d.%d - %d.%d\n", (int)phinfo->tv_start.tv_sec, (int)phinfo->tv_start.tv_usec,
           (int)phinfo->tv_end.tv_sec, (int)phinfo->tv_end.tv_usec);
    printk(KERN_INFO "process ID: %d\n", phinfo->usr_pid);
    printk(KERN_INFO "duration: %d.%d\n", sec, usec);
    printk(KERN_INFO "total packets: %d\n", phinfo->rx_pkts);
    printk(KERN_INFO "total bytes: %d\n", phinfo->rx_blen);
    // printk(KERN_INFO "byte rate: %f bytes/s\n", brate);
    // printk(KERN_INFO "packet rate: %f pkts/s\n", prate);

    /////////////////////////////
    if(phinfo->inter_dev)
        kfree(phinfo->inter_dev);

    if(phinfo->exter_dev)
        kfree(phinfo->exter_dev);

    if(phinfo->rule_list)
        rule_list_release(phinfo->rule_list);

    kfree(phinfo);
    MYDBG("tx packts: %d\n", tx_pkts);
    //TRACE_EXIT;
}

///////////////////////Memery map //////////////////////////////
#define TX_DEVICE_NAME "ktx"
#define RX_DEVICE_NAME "krx"

unsigned char *tx_buffer = NULL;
unsigned char *rx_buffer = NULL;
static wait_queue_head_t rxq;
static int flag = 0;
static struct tx_work *tx_worker = NULL;

static int tx_open(struct inode *inode, struct file *ftx)
{
	TRACE_ENTRY;
    tx_worker = (struct tx_work *)kmalloc(sizeof(struct tx_work), GFP_KERNEL);

    if(!tx_worker) {
        printk(KERN_ERR "%s(%d): malloc error.\n", __func__, __LINE__);
        return -EFAULT;
    }

    memset((void *)tx_worker, 0, sizeof(struct tx_work));
    TRACE_EXIT;
    return 0;
}

static int rx_open(struct inode *inode, struct file *frx)
{
    TRACE_ENTRY;
    init_nf_pktrx();
    TRACE_EXIT;
    return krx_rule_init();
}

static int rx_release(struct inode *inode, struct file *frx)
{
    TRACE_ENTRY;
    exit_nf_pktrx();

    if(tx_worker) {
        kfree(tx_worker);
        tx_worker = NULL;
    }

    krx_rule_list_release();
    TRACE_EXIT;
    return 0;
}

static int tx_release(struct inode *inode, struct file *rtx)
{
    //TRACE_ENTRY;
    //TRACE_EXIT;
    return 0;
}

static int tx_map(struct file *ftx, struct vm_area_struct *vma)
{
    //TRACE_ENTRY;
    unsigned long page = 0;
    //unsigned char  i;
    unsigned long start = (unsigned long)vma->vm_start;
    unsigned long size  = (unsigned long)(vma->vm_end - vma->vm_start);

    page = virt_to_phys(tx_buffer);

    if(!page) {
        printk(KERN_ERR "%s(%d):get phyical address error.\n", __func__, __LINE__);
        return -EFAULT;
    }

    if(remap_pfn_range(vma, start, page >> PAGE_SHIFT, size, PAGE_SHARED)) {
        printk(KERN_ERR "%s(%d): mmap phyical address error.\n", __func__, __LINE__);
        return -1;
    }

    TRACE_EXIT;
    return 0;
}

static int rx_map(struct file *frx, struct vm_area_struct *vma)
{
    TRACE_ENTRY;
    unsigned long page = 0;
    // unsigned char  i;
    unsigned long start = (unsigned long)vma->vm_start;
    unsigned long size  = (unsigned long)(vma->vm_end - vma->vm_start);
    unsigned char *tmp;
    page = virt_to_phys(rx_buffer);

    if(!page) {
        printk(KERN_ERR "%s(%d): get phyical address error.\n", __func__, __LINE__);
        return -EFAULT;
    }

    if(remap_pfn_range(vma, start, page >> PAGE_SHIFT, size, PAGE_SHARED)) {
        printk(KERN_ERR "%s(%d): mmap phyical address error.\n", __func__, __LINE__);
        return -1;
    }

    tmp = rx_buffer + sizeof(struct rx_msg);
    rx_buffer[0] = 100;
    //strcpy(tmp,"testtesttestrtx_device");
    tmp[0] = 1;
    TRACE_EXIT;
    return 0;
}

/* tx packet */
static int tx_fsync(struct file *ftx, loff_t s, loff_t e, int datasync)
{
    TRACE_ENTRY;
    int left = 0;
    struct pkt_schedule *pkt_sch = (struct pkt_schedule *)tx_buffer;

    if(pkt_sch->protocol == IPPROTO_UDP && pkt_sch->len < 28) {
        printk(KERN_ERR "%s(%d): Error UDP packet.\n", __func__, __LINE__);
        return -EFAULT;
    }

    if(pkt_sch->protocol == IPPROTO_TCP && pkt_sch->len < 40) {
        printk(KERN_ERR "%s(%d): Error TCP packet.\n", __func__, __LINE__);
        return -EFAULT;
    }

    if(pkt_sch->num < 1) {
        printk(KERN_ERR "%s(%d): Error TX packet number.\n", __func__, __LINE__);
        return -EFAULT;
    }

    if(!tx_worker) {
        printk(KERN_ERR "%s(%d): No TX worker mallocked.\n", __func__, __LINE__);
        return -EFAULT;
    }

    tx_worker->next_tx = timeval_to_ktime(pkt_sch->tx_start);
    tx_worker->delay   = timeval_to_ns(&pkt_sch->tv_delay);
    tx_worker->d = dev_get_by_name(&init_net, pkt_sch->ex_dev_name);
		tx_worker->work_type = pkt_sch->work_type;
    tx_worker->pkt_left = pkt_sch->num;
    tx_worker->ip_data = tx_buffer + sizeof(struct pkt_schedule);
    tx_worker->len = pkt_sch->len;
    printk(KERN_INFO "%s(%d): %s  %d (%llu, %llu, %d, %d, %d, %d)\n", __func__, tx_worker->work_type, pkt_sch->ex_dev_name, pkt_sch->num, tx_worker->next_tx, tx_worker->delay,
      pkt_sch->tx_start.tv_sec, pkt_sch->tx_start.tv_usec, pkt_sch->tv_delay.tv_sec, pkt_sch->tv_delay.tv_usec);
    left = ktx_xmit(tx_worker);
    TRACE_EXIT;
    return left;
}

/* add filter rules */
static int rx_fsync(struct file *frx, loff_t s, loff_t e, int datasync)
{
    TRACE_ENTRY;
    struct rx_rule_msg *rm = (struct rx_rule_msg *)rx_buffer;

    //printk(KERN_INFO "msg opt: %d\n", rm->type);
    if(rm->type == 0)
        krx_rule_clr();
    else {
        if(rm->type == 1) {
            krx_rule_add(&rm->tuple, NULL);
        }
    }

    TRACE_EXIT;
    return 0;
}

static unsigned int rx_poll(struct file *frx, poll_table *wait)
{
    TRACE_ENTRY;
    unsigned int mask = 0;
    poll_wait(frx, &rxq, wait);
   // printk("%s(%d): flag = %d\n", __func__, __LINE__, flag);

    if(flag != 0) {
        mask |= POLLIN | POLLRDNORM;
    }

    flag = 0;
    TRACE_EXIT;
    return mask;
}

static struct file_operations tx_fops = {
    .owner  = THIS_MODULE,
    .open   = tx_open,
    .release = tx_release,
    .mmap = tx_map,
    .fsync = tx_fsync,
};
static struct miscdevice tx_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = TX_DEVICE_NAME,
    .fops = &tx_fops,

};
static struct file_operations rx_fops = {
    .owner  = THIS_MODULE,
    .open   = rx_open,
    .mmap   = rx_map,
    .poll   = rx_poll,
    .fsync  = rx_fsync,
    .release = rx_release,
};
static struct miscdevice rx_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = RX_DEVICE_NAME,
    .fops = &rx_fops,
};

void rx_packet_wake(int len, struct timeval ts, unsigned char *data)
{
    //TRACE_ENTRY;
    struct rx_msg *rmsg = (struct rx_msg *)rx_buffer;
    unsigned char *d = rx_buffer + sizeof(struct rx_msg);
    rmsg->len = len;
    rmsg->ts = ts;
    memcpy(d, data, len);
    flag = len;
    wake_up(&rxq);
}

static int init_devices(void)
{
    int ret;
    TRACE_ENTRY;
    // printk("%s(%d): Init devices.\n", __func__, __LINE__);
    /* register rx and tx devices */
    ret = misc_register(&tx_misc);
    ret = misc_register(&rx_misc);
    // printk("mmap buffer size is %d bytes\n", PAGE_SIZE);

    /* alloc memery */
    tx_buffer = (unsigned char *)kmalloc(PAGE_SIZE, GFP_KERNEL);

    if(!tx_buffer) {
        printk("Malloc tx buffer error.\n");
        return 0;
    }
			//printk("tx_buffer: %x\n", tx_buffer);

    rx_buffer = (unsigned char *)kmalloc(PAGE_SIZE, GFP_KERNEL);

    if(!rx_buffer) {
        printk("Malloc rx buffer error.\n");
        return 0;
    }

    SetPageReserved(virt_to_page(tx_buffer));
    SetPageReserved(virt_to_page(rx_buffer));

    init_waitqueue_head(&rxq);


    TRACE_EXIT;
    return 1;
}

static int del_devices(void)
{
    TRACE_ENTRY;
    printk("%s(%d): Del devices.\n", __func__, __LINE__);
    /* deregister devices */
    misc_deregister(&rx_misc);
    misc_deregister(&tx_misc);

    ClearPageReserved(virt_to_page(rx_buffer));
    ClearPageReserved(virt_to_page(tx_buffer));

    if(rx_buffer)
        kfree(rx_buffer);

    if(tx_buffer)
        kfree(tx_buffer);
		return 0;
    TRACE_EXIT;
}

/* initiate this kernel module */
static int init_hijack(void)
{
    TRACE_ENTRY;
    plist = NULL;
    process_num = 0;

 /*   if(init_nl_comm() != 0) {
        printk(KERN_ERR "init netlink failure\n");
        return -1;
    }*/

    is_wait_exit = 0;
    init_devices();
    init_nf_pktrx();
    init_hash();
    rwlock_init(&list_hijack_lock);
		printk(KERN_INFO "KRT have been installed.\n");
    TRACE_EXIT;
    return 0;
}

/* cleanup this kernel module */
static void cleanup_hijack(void)
{
    struct pkt_hijack_info *tmp, *phinfo;
    TRACE_ENTRY;
  //  exit_nl_comm(); /* release the netlink module */
	  exit_nf_pktrx();
    is_wait_exit = 1;
    tmp = plist;

    while(tmp) {
        phinfo = tmp;
        tmp = tmp->next;
        del_hijack_process(phinfo);
    }

    del_devices();
    xmit_exit();
		printk(KERN_INFO "KRT have been removed.\n");
    TRACE_EXIT;
}

module_init(init_hijack);
module_exit(cleanup_hijack);
