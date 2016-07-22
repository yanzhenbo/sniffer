#include "../Include/http_handler.h"
extern int vivid;
extern int hex;
void http_handler(const u_char *packet, int type, int len)
{
	typedef struct {
		int len;
		u_char data[0];
	} buffer;
	if(vivid) {
		printf("\n");
	}
	printf("\tHTTP\n");
    for(;;) {
		int i;
		for(i = 0; i < len - 1 && 0 != strncmp(packet + i, "\r\n", 2); i++);
		if(i == len - 1) {						// a part of http packet 
			i = len;
		}	
		buffer *line = (buffer*)malloc(sizeof(buffer) + i + 1);
		memcpy(line->data, packet, i);
		line->data[i] = '\0';
		if(i == len) {							// http packet is truncated
			if(vivid) {
				printf("\t%s\n", line->data);
			}
			packet += len;
			len = 0;
			break;
		}
		else {
			if(vivid) {
				printf("\t%s\\r\\n\n", line->data);
			}
			packet += (i + 2);
			len -= (i + 2);
		}

		if(0 == i){				// the line begin with "\r\n"
			break;
		}
	}
	if(hex) {
		print_payload(packet, len);
	}
	return;
}
