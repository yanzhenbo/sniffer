#ifndef _EHTER_HANDLER_H_
#define _EHTER_HANDLER_H_ 1
#include "../Include/print.h"
#include "../Include/ip_handler.h"
#include "../Include/arp_handler.h"
#include "../Include/statistic.h"
#include <stdio.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

/* ethernet headers are always exactly 14 bytes */
#ifndef SIZE_EHTERNET 
#define SIZE_ETHERNET 14
#endif 

/* Ethernet addresses are 6 bytes */
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN	6
#endif

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

void ether_handler(const u_char *packet, int len);
#endif /* _EHTER_HANDLER_H_ */
