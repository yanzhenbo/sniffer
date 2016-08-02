#include "../Include/modbus_handler.h"
//extern int vivid;
//extern int hex;

extern struct recorder myRecorder;
extern MYSQL mysql;
extern MYSQL_RES *res;
extern MYSQL_ROW row;
extern char query[200];
extern char table_name[50];

void modbus_handler(const u_char *packet, int len)
{
	const struct sniff_mbap *mbap;
	
	u_short mb_transId;
	u_short mb_protoId;
	u_short mb_len;
	u_char mb_unitId;
	
	memcpy(myRecorder.protocol_type, "MODBUS\0", 7);
	//printf("\tModbus Protocol\n");

	mbap = (struct sniff_mbap*)(packet);
	
	if(len < 7) {
		printf("	* Invalid mbap length: %d bytes\n", len);
		return;
	}

	mb_transId = ntohs(mbap->mb_transId);
	mb_protoId = ntohs(mbap->mb_protoId);
	mb_len = ntohs(mbap->mb_len);
	mb_unitId = mbap->mb_unitId;
#if 0
	if(vivid) {
		printf("\ttransaction Id: %u\n", mb_transId);
		printf("\tprotocol Id: %u\n", mb_protoId);
		printf("\tlength: %u\n", mb_len);
		printf("\tunit Id: %u\n", mb_unitId);
	}
#endif
	packet += MBAP_HEADER_LEN;
    len -= MBAP_HEADER_LEN;	
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
