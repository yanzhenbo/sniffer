#ifndef _HTTP_HANDLER_H_
#define _HTTP_HANDLER_H_ 1
#include "mysql_handler.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "print.h"
void http_handler(const u_char *packet, int type, int len); //type == 1 is a request, 2 is a response

#endif /* _HTTP_HANDLER_H_ */
