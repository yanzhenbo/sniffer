#ifndef _MODBUS_HANDLER_H_
#define _MODBUS_HANDLER_H_ 1
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

#define MBAP_HEADER_LEN 7

/* MBAP packet header */
struct sniff_mbap {
	u_short mb_transId;
	u_short mb_protoId;
	u_short mb_len;
	u_char mb_unitId;
};
void modbus_handler(const u_char *packet, int len);

#endif /* _MODBUS_HANDLER_H_ */
