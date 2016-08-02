#include "../Include/http_handler.h"
#include "../Include/mysql_handler.h"
//extern int vivid;
//extern int hex;


extern struct recorder myRecorder;
extern MYSQL mysql;
extern MYSQL_RES *res;
extern MYSQL_ROW row;
extern char query[200];
extern char table_name[50];

void http_handler(const u_char *packet, int type, int len)
{
	memcpy(myRecorder.protocol_type, "HTTP\0", 5);
	typedef struct {
		int len;
		u_char data[0];
	} buffer;
#if 0
	if(vivid) {
		printf("\n");
	}
	printf("\tHTTP\n");
#endif
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
#if 0
			if(vivid) {
				printf("\t%s\n", line->data);
			}
#endif
			packet += len;
			len = 0;
			break;
		}
		else {
#if 0
			if(vivid) {
				printf("\t%s\\r\\n\n", line->data);
			}
#endif
			packet += (i + 2);
			len -= (i + 2);
		}

		if(0 == i){				// the line begin with "\r\n"
			break;
		}
	}
#if 0
	if(hex) {
		print_payload(packet, len);
	}
#endif
	
	
	int t = insert(&mysql, table_name, myRecorder);
	if(t) {
		printf("执行显示时出现异常：%s", mysql_error(&mysql));
	}
	else {
		printf("插入成功\n");
	}

	return;
}
