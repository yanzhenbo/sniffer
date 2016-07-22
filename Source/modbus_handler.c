#include "../Include/modbus_handler.h"
extern int vivid;
extern int hex;
void modbus_handler(const u_char *packet, int len)
{
	const struct sniff_mbap *mbap;
	
	u_short mb_transId;
	u_short mb_protoId;
	u_short mb_len;
	u_char mb_unitId;

	printf("\tModbus Protocol\n");

	mbap = (struct sniff_mbap*)(packet);
	
	if(len < 7) {
		printf("	* Invalid mbap length: %d bytes\n", len);
		return;
	}

	mb_transId = ntohs(mbap->mb_transId);
	mb_protoId = ntohs(mbap->mb_protoId);
	mb_len = ntohs(mbap->mb_len);
	mb_unitId = mbap->mb_unitId;
	if(vivid) {
		printf("\ttransaction Id: %u\n", mb_transId);
		printf("\tprotocol Id: %u\n", mb_protoId);
		printf("\tlength: %u\n", mb_len);
		printf("\tunit Id: %u\n", mb_unitId);
	}
	packet += MBAP_HEADER_LEN;
    len -= MBAP_HEADER_LEN;	
	if(hex) {
		print_payload(packet, len);
	}
	return;
}
