// log.c

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <linux/init.h>
#include <stdarg.h>

#include "log.h"
struct timeval pkt_tv[200][100];
unsigned int packets[200];
static struct file *log_file = NULL;
void add(int len, struct timeval tv)
{
  int i = (len-54)/10;
  pkt_tv[i][packets[i]] = tv;
  packets[i]++;
}
/*void add(int i, int j, struct timeval tv)
{
  pkt_tv[i][j] = tv;
}*/


int init_log(char *file_path)
{
  int i, j;
  printk("Initial log file. \n");		
  if(log_file == NULL)
  {
    log_file = filp_open(file_path, O_RDWR | O_APPEND | O_CREAT, 0644);
    if(IS_ERR(file_path))
    {
      printk("Error occured while opening file %s, exiting...\n", file_path);
      return 0;
    }
  }
  for(i = 0; i < 200; i++)
  {
    packets[i] = 0;
    for(j = 0; j<100; j++)
    {
      pkt_tv[i][j].tv_sec= 0;
      pkt_tv[i][j].tv_usec=0;
    }
  }
  return 1;
}

int my_log(const char *fmt, ...)
{
  va_list ap;
  char buf[256];
  int n = 0;
  mm_segment_t old_fs;
  va_start(ap, fmt);
  n = vsprintf(buf, fmt, ap);
  va_end(ap);
  if(log_file == NULL)
    return 0;
  old_fs = get_fs();
  set_fs(KERNEL_DS);
  log_file->f_op->write(log_file, buf, n, &log_file->f_pos);
  set_fs(old_fs);
  
  return n;  
} 

void exit_log(void)
{
  int i, j;
  
  if(log_file != NULL)
  {
     for(i=0;i<200;i++)
     {
       my_log("%d %d", i, packets[i]);
       for(j=0;j<packets[i];j++)
       {
	 my_log(" %d.%d", pkt_tv[i][j].tv_sec, pkt_tv[i][j].tv_usec);
       }
       my_log("\n");
     }
     filp_close(log_file, NULL);
     log_file = NULL;
  }
}
