#include "../Include/arp_handler.h"
//extern int vivid;
void arp_handler(const u_char *packet, int len)
{
	const struct sniff_arp *arp;

	//printf("ARP\n");
	arp = (struct sniff_arp*)(packet);

#if 0
	if(vivid) {
		printf("	Hardware type: 0x%04x\n", ntohs(arp->ar_hrd));
		printf("	Protocol type: 0x%04x\n", ntohs(arp->ar_pro));
		printf("	Hardware size: %u\n", arp->ar_hln);
		printf("	Protocol size: %u\n", arp->ar_pln);
		printf("	Opcode: %u\n", ntohs(arp->ar_op));
	}
#endif

#if 0
	printf("	Sender MAC address: ");
	print_ether_addr(arp->ar_sha);
	printf("\n	Sender IP address: %s\n", inet_ntoa(arp->ar_sip));
	printf("	Target MAC address: ");
	print_ether_addr(arp->ar_tha);
	printf("\n	Target IP address: %s\n", inet_ntoa(arp->ar_tip));
#endif
	return;
}
