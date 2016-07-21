#include "../Include/statistic.h"

int proto[PROTO_CATEGORY];

void proto_stat_print()
{
	printf("\tProcoal\tNumber\n");
	printf("\tIP\t%d\n", proto[IP_INDEX]);
	printf("\tICMP\t%d\n", proto[ICMP_INDEX]);
	printf("\tTCP\t%d\n", proto[TCP_INDEX]);
	printf("\tUDP\t%d\n", proto[UDP_INDEX]);
	printf("\tHTTP\t%d\n", proto[HTTP_INDEX]);
	printf("\tFTP\t%d\n", proto[FTP_INDEX]);
	printf("\tTELNET\t%d\n", proto[TELNET_INDEX]);
	printf("\tMODBUS\t%d\n", proto[MODBUS_INDEX]);
	return;
}
