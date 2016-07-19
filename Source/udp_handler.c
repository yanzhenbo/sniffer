#include "../Include/udp_handler.h"
extern int vivid;
void udp_handler(const u_char *packet, int len)
{
	const struct sniff_udp *udp;

	int size_udp;
	u_short sport;
	u_short dport;
	printf("\tUDP\n");
	size_udp = sizeof(struct sniff_udp);
	udp = (struct sniff_udp*)(packet);
	sport = ntohs(udp->uh_sport);
	dport = ntohs(udp->uh_dport);
	printf("\tSrc port: %u", sport);
	printf("\tDst port: %u\n", dport);
	if(vivid) {
		printf("	Total length: %u\n", ntohs(udp->uh_ulen));
		printf("	Checksum: 0x%04x\n", ntohs(udp->uh_checksum));
	}
	return;
}
