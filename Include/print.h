#ifndef _PRINT_H_
#define _PRINT_H_ 1
#include "../Include/ether_handler.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>		/* isprintf */
#include <sys/socket.h>

#define APP_NAME		"sniffer"
#define APP_DESC		"Sniffer packet of ip, tcp, udp, http etc using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2016 IIE"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_app_banner(void);
void print_app_usage(void);
void print_ether_addr(const u_char *packet);

#endif /* _PRINT_H_ */

