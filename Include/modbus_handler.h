#ifndef _MODBUS_HANDLER_H_
#define _MODBUS_HANDLER_H_ 1
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
void modbus_handler(const u_char *packet, int len);

#endif /* _MODBUS_HANDLER_H_ */
