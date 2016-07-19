#include "../Include/ftp_handler.h"
extern int vivid;
void ftp_handler(const u_char *packet, int type, int len)
{
	typedef struct {
		int len;
		u_char data[0];
	} buffer;
	printf("	FTP\n");
	if (1 == type ) {
			int i;
			for(i = 0; i < len - 1 && 0 != strncmp(packet + i, "\r\n", 2); i++);
			if(i == len - 1) {
				i = len;
			}
			buffer *line = (buffer*)malloc(sizeof(buffer) + i + 1);
			memcpy(line->data, packet, i);
			line->data[i] = '\0';
			if(vivid) {
				if(i == len) {
					printf("\t%s\n", line->data);
				}
				else {
					printf("\t%s\\r\\n\n", line->data);
				}
			}
	}
	else if(2 == type) {
			buffer *line = (buffer*)malloc(sizeof(buffer) + len + 1);
			memcpy(line->data, packet, len);
			line->data[len] = '\0';
			if(vivid) {
				printf("\tFTP Data (%d bytes data)\n", len);
			}
	}
	else {

	}

	return;
}
