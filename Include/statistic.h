#ifndef _STATISTIC_H_
#define _STATISTIC_H_ 1
#include <stdio.h>
#define PROTO_CATEGORY 100
#define UNKNOWN_INDEX 0
#define ARP_INDEX 1
#define RARP_INDEX 2
#define IP_INDEX 3
#define ICMP_INDEX 4
#define TCP_INDEX 5
#define UDP_INDEX 6
#define HTTP_INDEX 7
#define FTP_INDEX 8
#define TELNET_INDEX 9
#define MODBUS_INDEX 10

void proto_stat_print();
#endif /* _STATISTIC_H_ */
