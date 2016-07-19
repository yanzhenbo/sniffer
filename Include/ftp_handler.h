#ifndef _FTP_HANDLER_H_
#define _FTP_HANDLER_H_ 1
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
void ftp_handler(const u_char *packet, int type, int len);  // type == 1 is a control connect, 2 is data

#endif /* _FTP_HANDLER_H_ */
