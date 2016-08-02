#ifndef _PACKET_HANDLER_H_
#define _PACKET_HANDLER_H_ 1
#include "ether_handler.h"
#include "mysql_handler.h"
#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif /* _PACKET_HANDLER_H_ */
