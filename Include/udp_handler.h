#ifndef _UDP_HANDLER_H_
#define _UDP_HANDLER_H_ 1
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* UDP header */
struct sniff_udp {
		u_short uh_sport;				/* source port */
		u_short uh_dport;				/* destination port */
		u_short uh_ulen;				/* udp length */
		u_short uh_checksum;			/* udp checksum */
};

void udp_handler(const u_char *packet, int len);
#endif /*_UDP_HANDLER_H_ */
