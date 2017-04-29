
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include<linux/ioctl.h>
//#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <malloc.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
//#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <time.h>
#include <linux/netdevice.h>
#include <linux/icmp.h>
//#include <linux/time.h>
#include <linux/types.h>
#include <pthread.h>


#include "testu.h"
//#include "debug.h"

#define TRACE_ENTRY printf("Entering %s\n", __func__)
#define TRACE_EXIT  printf("Exiting %s\n", __func__)

#define PAGE_SIZE 4096
#define	MAXINTERFACES 16

static int tx_fd = -1;
static int rx_fd = -1;
//static int is_rx_running = 0;
//static int is_tx_running = 0;
unsigned char *tx_map = NULL;
unsigned char *rx_map = NULL;

static measure_info *m_cfg = NULL;
static measure_res m_res[10];
static pthread_t krtx_thread_rcv;
static pthread_t krtx_thread_snd;

static unsigned short id;

static int datalen = 1470;

char *krtx_inet_ntoa(const unsigned int addr, char *buf)
{
	u_char s1 = (addr & 0xFF000000) >> 24;
	u_char s2 = (addr & 0x00FF0000) >> 16;
	u_char s3 = (addr & 0x0000FF00) >> 8;
	u_char s4 = (addr & 0x000000FF);
	sprintf(buf, "%d.%d.%d.%d", s4, s3, s2, s1);
	return buf;
}

uint16_t csum(u_char *addr, int count)
{
	/* Compute Internet Checksum for "count" bytes
	 *         beginning at location "addr".
	 */
	register int sum = 0;

	while(count > 1)  {
		/*  This is the inner loop */
		sum += *((unsigned short *)addr);
		addr += 2;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if(count > 0)
		sum += *(unsigned char *) addr;

	/*  Fold 32-bit sum to 16 bits */
	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

//used for computing the tcp checksum
struct psd_header {
	unsigned int saddr; // sip
	unsigned int daddr; // dip
	u_char mbz;// 0
	u_char ptcl; // protocol
	unsigned short tcpl; //TCP lenth

};

uint16_t tcp_csum(uint32_t saddr, uint32_t daddr, u_char *tcppkt, uint16_t len)
{
	u_char buf[1600], *pkt;
	uint16_t rst;
	struct psd_header *psdh;
	struct tuple5 {
		unsigned int sip;
		unsigned int dip;
		unsigned short sport;
		unsigned short dport;
		unsigned char protocol;
	};
	int count = sizeof(struct psd_header) + len;
	memset(buf, 0, count);
	//TRACE_ENTRY;
	psdh = (struct psd_header *)buf;
	pkt = buf + sizeof(struct psd_header);
	psdh->saddr = saddr;
	psdh->daddr = daddr;
	psdh->mbz = 0;
	psdh->ptcl = IPPROTO_TCP;
	psdh->tcpl = htons(len);
	memcpy(pkt, tcppkt, len);
	rst = csum(buf, count);
	//TRACE_EXIT;
	return rst;
}



unsigned int pkts = 0, bytes = 0;
struct timeval tv_start, tv_end;
// process the rx packets

static char load_avg[255];
void get_load_avg()
{
	FILE *fp;
	memset(load_avg, 0, 255);
	if((fp = fopen("/proc/loadavg", "r")) == NULL)
	{
		return;
	}
	fread(load_avg, 1, 16, fp);
	fclose(fp);

}


// initialize a start ack number through generating a random number
	unsigned int
init_ackseq()
{
	srand((unsigned int)time(NULL));
	return rand();
}

// get the ip address of the ethernet device
	unsigned int
get_local_ip(char *eth)
{
	int sock;
	struct ifconf ifconf;
	struct ifreq ifreq[MAXINTERFACES];
	int interfaces;
	int i;
	unsigned int sip = 0;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0) {
		//printf("%d: Create socket error.\n", __LINE__);
		return 0;
	}
	ifconf.ifc_buf = (char *)ifreq;
	ifconf.ifc_len = sizeof(ifreq);
	if(ioctl(sock, SIOCGIFCONF, &ifconf) == -1) {
		close(sock);
		//printf("%d: ioctl error.\n", __LINE__);
		return 0;
	}
	interfaces = ifconf.ifc_len / sizeof(ifreq[0]);
	for(i = 0; i < interfaces; i++) {
		char ip[INET_ADDRSTRLEN];
		struct sockaddr_in *address = (struct sockaddr_in *) &ifreq[i].ifr_addr;
		// Convert the binary IP address into a readable string.
		if(!inet_ntop(AF_INET, &address->sin_addr, ip, sizeof(ip))) {
			//printf("%d: inet_ntop error ..\n");
			continue;
		}
		if(strcmp(ifreq[i].ifr_name, eth) == 0) {
			sip = inet_addr(ip);
			printf("%s\t%s\n", ifreq[i].ifr_name, ip);
			break;
		}
	}
	close(sock);
	return sip;
}

static void rule_add(unsigned int src, unsigned int dst,
		unsigned short sport, unsigned short dport,
		unsigned short protocol)
{
	//TRACE_ENTRY;
	struct rx_rule_msg *rmsg = (struct rx_rule_msg *)rx_map;
	rmsg->type = 1;
	rmsg->tuple.sip = src;
	rmsg->tuple.dip = dst;
	rmsg->tuple.sport = sport;
	rmsg->tuple.dport = dport;
	rmsg->tuple.protocol = protocol;
	fsync(rx_fd);
}


static int pkt_sch(unsigned char *pkt, int num, unsigned int len)
{
	//TRACE_ENTRY;
	struct pkt_schedule *psch = (struct pkt_schedule *)tx_map;
	unsigned char *data = tx_map + sizeof(struct pkt_schedule);
	int res = 0;
	if(tx_fd < 0)
	{
		printf("Open file error.\n");
		return;
	}

	psch->work_type= WORK_TYPE_BAND;
	psch->len = len;
	psch->num = num;
	psch->tv_delay.tv_sec = m_cfg->gap.tv_sec;
	psch->tv_delay.tv_usec = 0;
	//psch->tx_start = start;
	strcpy(psch->ex_dev_name, m_cfg->eth);
	memcpy(data, pkt, len);
	//printf("tx: datalen = %d bytes pkts = %d\n", len, num);
	res = fsync(tx_fd);
	printf("res = %d\n", res);
}

unsigned char pkt_buf[10240];

double get_current_ts()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}


int pkt_construct(unsigned int seq)
{
	int pktlen = 0, i = 0;
	unsigned char *ip_buf = NULL;//kmalloc(pktlen, GFP_KERNEL);
	struct iphdr *iph = NULL;//(struct iphdr *)ip_buf;
	struct udphdr *udph = NULL;
	char *data = NULL, buf1[16], buf2[16];//ip_buf + sizeof(struct iphdr) + sizeof(struct tcphdr);
	pktlen = sizeof(struct iphdr) + sizeof(struct icmphdr) + datalen;

	//printf("pktlen = %d (%d %d %D)\n", pktlen, sizeof(struct iphdr), sizeof(struct icmphdr), datalen);
	ip_buf = pkt_buf;
	iph = (struct iphdr *) ip_buf;
	memset(ip_buf, 0, pktlen);
	iph->version = 0x4;
	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->frag_off = htons(IP_DF);
	iph->protocol = IPPROTO_UDP;
	iph->tos = 0;
	iph->daddr = m_cfg->dip; // inet_addr("158.132.255.23");
	iph->saddr = m_cfg->sip; // inet_addr("158.132.255.62");
	//printf("%s  --> %s\n",  tt_inet_ntoa(iph->saddr, buf1), tt_inet_ntoa(iph->daddr, buf2));
	iph->ttl = 0x40;

	iph->tot_len = htons(pktlen);
	iph->check = 0;
	iph->id = htons(0x777);
	iph->check = csum((void *) iph, iph->ihl * 4);
	udph = (struct udphdr *)(ip_buf + sizeof(struct iphdr));
	udph->source	= htons(5001);
	udph->dest		= htons(5002);
	udph->len			= htons(datalen + sizeof(struct udphdr));
	data = ip_buf + sizeof(struct iphdr) + sizeof(struct udphdr);
	for(i = 0; i < datalen; i++)
		data[i] = i;
	gettimeofday((struct timeval *)data, NULL);
	//icmph->checksum = csum((unsigned short *)icmph, sizeof(struct icmphdr) + datalen);
	return pktlen;
}

void do_measure()
{
	//TRACE_ENTRY;
	int pktlen = 0, i = 0;
	if(m_cfg->is_tx){
		pktlen = pkt_construct(++i);
		pkt_sch(pkt_buf, 1, pktlen);
		sleep(1);
		//break;
	}

	m_cfg->is_rx = 0;
	m_cfg->is_tx = 0;
}
static void tx_exit()
{
	//TRACE_ENTRY;

	if(tx_fd > 0) {
		munmap(tx_map, PAGE_SIZE);
		close(tx_fd);
		tx_fd = -1;
	}
}
static int tx_init()
{
	tx_fd = open("/dev/ktx", O_RDWR);

	if(tx_fd < 0) {
		printf("tx: open fail\n");
		return 0;
	}

	printf("tx: fd = %d\n", tx_fd);
	// Memery mapping
	tx_map = (unsigned char *)mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, tx_fd, 0);

	if(tx_map == MAP_FAILED) {
		close(tx_fd);
		tx_fd = -1;
		printf("tx: mmap fail\n");
		return 0;
	}

	printf("tx_map: %x\n", tx_map);
	return 1;
}
void thread_tx()
{
	do_measure();
}

int ip_process(char *ipbuf, struct timeval tv_rx, int len)
{
	struct iphdr  *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct timeval now;
	char buf1[16], buf2[16], *payload = NULL, *data = NULL;
	int i = 0;
	static int rx_num, rx_len;
	double ts = (double)tv_rx.tv_sec + (double)tv_rx.tv_usec / 1000000.0;

	iph = (struct iphdr *)ipbuf;

	if(len != ntohs(iph->tot_len)) {
		printf("%4d received uncomplete packet(%d %d)\n", iph->id, len, ntohs(iph->tot_len));
		return -1;
	}

	// log
	gettimeofday(&now, NULL);

	switch(iph->protocol) {
		case IPPROTO_UDP:
			udph = (struct tcphdr *)(iph + 1);
			payload = (char *)(udph + 1);
			data = payload;
			if((unsigned char)(*data) != WORK_TYPE_BAND)
				return 0;
			data++;
			int datalen = *(int *)data;
			data += sizeof(int);
			int rxnum = *(int *)data;
			data += sizeof(int);
			int txnum = *(int *)data;
			double b = (double)datalen / ts * 8.0 / 1024.0 / 1024.0;
			printf("bandwidth=%f Mbit/s  loss rate = %d %d\n", b, txnum, rxnum);
			break;
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)((char *)iph + (iph->ihl << 2));

			if(tcph->ack && tcph->syn) {
				for(i = 0; (i < m_cfg->tx_pkts) && (m_res[i].sport != 0); i++) {
					if(ntohs(tcph->dest) == m_res[i].sport) {
						m_res[i].tv_rx = tv_rx;
						break;
					}
				}
			}
			printf("%f: %s:%d->%s:%d id = %x len = %d(%d)\n", ts, krtx_inet_ntoa(iph->saddr, buf1), ntohs(tcph->source), krtx_inet_ntoa(iph->daddr, buf2),
					ntohs(tcph->dest), ntohs(iph->id), len, ntohs(iph->tot_len));
			break;
		case IPPROTO_ICMP:
			payload = ipbuf  + sizeof(struct iphdr) + sizeof(struct icmphdr);
			printf("%s->%s rtt=%f ms\n", krtx_inet_ntoa(iph->saddr, buf1), krtx_inet_ntoa(iph->daddr, buf2), ts*1000.0);
			// printf("icmp packet\n");
			break;
		default:
			break;
	}
	rx_num++;
	if(rx_num > 1 && rx_len != len) {
		printf("Recieved %d %d bytes packets.\n", rx_num, rx_len);
		rx_num == 0;
	}
	rx_len = len;
	return 0;
}
static void rx_exit()
{
	//TRACE_ENTRY;

	if(rx_fd > 0) {
		munmap(rx_map, PAGE_SIZE);
		close(rx_fd);
		tx_fd = -1;
	}
}
static int rx_init()
{
	//TRACE_ENTRY;
	rx_fd = open("/dev/krx", O_RDWR, S_IRUSR | S_IWUSR);

	if(rx_fd < 0) {
		printf("rx: open fail\n");
		return 0;
	}

	printf("rx: fd = %d\n", rx_fd);

	// Memory mapping
	rx_map = (unsigned char *)mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, rx_fd, 0);

	//printf("debug1\n");
	if(rx_map == MAP_FAILED) {
		printf("rx: mmap fail\n");
		close(rx_fd);
		rx_fd = -1;
		return 0;
	}

	return 1;
}

void thread_rx()
{
	fd_set rxds;
	struct timeval tv;
	struct timeval ts;
	struct rx_msg *rmsg = NULL;
	unsigned char *ippkt = NULL;
	int i = 0;
	// Open device
	rmsg = (struct rx_msg *)rx_map;
	ippkt = rx_map + sizeof(struct rx_msg);
	i = 0;

	//is_rx_running = 1;
	if(m_cfg->is_rx)
		rule_add(m_cfg->dip, 0, htons(m_cfg->dport), 0, IPPROTO_UDP);

	while(m_cfg->is_rx & rx_fd > 0) {
		i++;
		gettimeofday(&ts, NULL);
		printf("start: %u.%u\n", ts.tv_sec, ts.tv_usec);
		FD_ZERO(&rxds);
		//printf("debug3\n");
		FD_SET(rx_fd, &rxds);

		tv.tv_sec = 2;
		tv.tv_usec = 0;
		gettimeofday(&ts, NULL);
		// printf("start: %u.%u\n", ts.tv_sec, ts.tv_usec);
		select(rx_fd + 1, &rxds, NULL, NULL, &tv);
		gettimeofday(&ts, NULL);
		// printf("stop:  %u.%u\n", ts.tv_sec, ts.tv_usec);

		if(FD_ISSET(rx_fd, &rxds)) {
			gettimeofday(&ts, NULL);
			// printf("rx:  %u.%u\n", ts.tv_sec, ts.tv_usec);
			// t = (struct test *)p_map;
			ip_process(ippkt, rmsg->ts, rmsg->len);
		}
		else {
			printf("No data within 5 seconds.\n");
		}
	}

	return 0;
}

void terminate(int signo)
{
	m_cfg->is_rx = 0;
	m_cfg->is_tx = 0;
	sleep(2);
	tx_exit();
	rx_exit();
	printf("\nexit\n");
	exit(1);
}

void print_help()
{
	printf("USAGE:");
	printf("Example: ./kping -i eth0 -d 192.168.1.1\n");
	printf("-i device name\n");
	printf("-d destination ip\n");
	printf("-t duration (s)\n");
}

int get_conf(int argc, char *argv[])
{
	char opt;
	double tmp;
	m_cfg = (measure_info *)malloc(sizeof(measure_info));

	if(m_cfg == NULL) {
		printf("Malloc m_cfg error..\n");
		return 0;
	}

	m_cfg->is_rx = 1;
	m_cfg->is_tx = 1;
	m_cfg->iterates = 1;

	//memset((char *)m_cfg, 0, sizeof(m_cfg));
	while((opt = getopt(argc, argv, "i:d:p:h:g:n:T:l:r:t:I:c:")) != -1) {
		switch(opt) {
			case 'i':
				strcpy(m_cfg->eth, optarg);
				break;
			case 'd':
				m_cfg->dip = inet_addr(optarg);
				break;
			case 'h':
				print_help();
				break;
			case 't':
				m_cfg->gap.tv_sec = atoi(optarg);
				break;
			default:
				break;
		}
		if(opt == 255)
			break;
	}
	m_cfg->is_tx = 1;
	m_cfg->is_rx = 1;
	printf("%d %p\n",strlen(m_cfg->eth), m_cfg->dip);
	if((strlen(m_cfg->eth) > 0) && (m_cfg->dip > 0))
		return 1;
	else
		return 0;

}

// ./test -i eth0 -d 192.168.1.1 -p 80
int main(int argc, char *argv[])
{
	if(get_conf(argc, argv) == 0) {
		printf("input param error..\n");
		print_help();
		return 0;
	}

	if(signal(SIGINT, terminate) == SIG_ERR) {
		printf("error during initialize signal handler.\n");
		return 0;
	}

	tx_init();
	rx_init();

	if(m_cfg->is_tx && (m_cfg->sip = get_local_ip(m_cfg->eth)) == 0) {
		printf("get source ip error.\n");
		return 0;
	}

	if(pthread_create(&krtx_thread_rcv, NULL, thread_rx, NULL) != 0) {
		perror("Create rx thread failure!\n");
		return -1;
	}

	if(pthread_create(&krtx_thread_snd, NULL, thread_tx, NULL) != 0) {
		perror("Create tx thread failture\n");
		return -1;
	}

	pthread_join(krtx_thread_snd, NULL);

	pthread_join(krtx_thread_rcv, NULL);
	// config in code


	//usleep(3);
	tx_exit();
	rx_exit();
	return 0;
}
