#ifndef _LOG_H
#define _LOG_H

void add(int len, struct timeval tv);
//void add(int i, int j, struct timeval tv);
int init_log(char *logfile);
int my_log(const char *fmt, ...);
void exit_log(void);

#endif// _LOG_H
