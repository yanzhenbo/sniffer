#include "../Include/ftp_handler.h"
#include "../Include/mysql_handler.h"
//extern int vivid;
//extern int hex;

extern struct recorder myRecorder;
extern MYSQL mysql;
extern MYSQL_RES *res;
extern MYSQL_ROW row;
extern char query[200];
extern char table_name[50];

void ftp_handler(const u_char *packet, int type, int len)
{
	memcpy(myRecorder.protocol_type, "FTP\0", 4);

	typedef struct {
		int len;
		u_char data[0];
	} buffer;
//	printf("\tFTP\n");
	if (1 == type ) {
			int i;
			for(i = 0; i < len - 1 && 0 != strncmp(packet + i, "\r\n", 2); i++);
			if(i == len - 1) {
				i = len;
			}
			buffer *line = (buffer*)malloc(sizeof(buffer) + i + 1);
			memcpy(line->data, packet, i);
			line->data[i] = '\0';
#if 0
			if(vivid) {
				if(i == len) {
					printf("\t%s\n", line->data);
				}
				else {
					printf("\t%s\\r\\n\n", line->data);
				}
			}
#endif
	}
	else if(2 == type) {
			buffer *line = (buffer*)malloc(sizeof(buffer) + len + 1);
			memcpy(line->data, packet, len);
			line->data[len] = '\0';
#if 0
			if(vivid) {
				printf("\tFTP Data (%d bytes data)\n", len);
			}
#endif
	}
	else {

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
