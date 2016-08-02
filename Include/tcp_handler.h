#ifndef _TCP_HANDLER_H_
#define _TCP_HANDLER_H_ 1

#include "http_handler.h"
#include "telnet_handler.h"
#include "ftp_handler.h"
#include "statistic.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_short  th_hl_flags;               /* header length, rsvd, flags */
		#define TH_HL(th)      ((ntohs((th)->th_hl_flags) & 0xf000) >> 12)
        #define TH_FIN  0x0001
        #define TH_SYN  0x0002
        #define TH_RST  0x0004
        #define TH_PUSH 0x0008
        #define TH_ACK  0x0010
        #define TH_URG  0x0020
        #define TH_ECE  0x0040
        #define TH_CWR  0x0080
		#define TH_NS	0x0100
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CWR|TH_NS)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
void tcp_handler(const u_char *packet, int len);
#endif /* _TCP_HANDLER_H_ */

