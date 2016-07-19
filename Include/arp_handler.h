#ifndef _ARP_HANDLER_H_
#define _ARP_HANDLER_H_ 1

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
struct sniff_arp {
		u_short ar_hrd;					/* Format of hardware address */
		u_short ar_pro;					/* Format of protocol address */
		u_char ar_hln;					/* Length of hardware address */
		u_char ar_pln;					/* Length of protocol address */
		u_short ar_op;					/* ARP opcode (command) */
#if 0
		u_char ar_sha[ETHER_ADDR_LEN];	/* Sender hardware address */
		struct in_addr ar_sip;				/* Sender IP address */
		u_char ar_tha[ETHER_ADDR_LEN];	/* Target hardware address */
		struct in_addr ar_tip;				/* Target IP address */
#endif
};

void arp_handler(const u_char *packet, int len);
#endif /* _APR_HANDLER_H_ */
