#ifndef _TELNET_HANDLER_H_
#define _TELNET_HANDLER_H_ 1
#include "mysql_handler.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

void telnet_handler(const u_char *packet, int len);
char *telnet_command(u_char com_code);
char *telnet_option(u_char opt_code);
#endif  /* _TELNET_HANDLER_H_  */
