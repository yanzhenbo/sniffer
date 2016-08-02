#include "../Include/ether_handler.h"
//extern int proto[PROTO_CATEGORY];
//extern int vivid;
void ether_handler(const u_char *packet, int len)
{
	const struct sniff_ethernet *ethernet;	/* The ethernet header  */
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	len -= SIZE_ETHERNET;
	packet += SIZE_ETHERNET;
#if 0
	if(vivid) {
		printf("	Ethernet II,Src:");
		print_ether_addr(ethernet->ether_shost);
		printf(", Dst: ");
		print_ether_addr(ethernet->ether_dhost);
		printf(", Type:  ");
	}
#endif
	switch(ntohs(ethernet->ether_type)) {
		case ETHERTYPE_IP:
			//proto[IP_INDEX] ++;
			ip_handler(packet, len);
			break;
		case ETHERTYPE_ARP:
			//proto[ARP_INDEX] ++;
			//arp_handler(packet, len);
			break;
		case ETHERTYPE_REVARP:
			//printf("RARP\n");
			break;
		case ETHERTYPE_PUP:
			//printf("Xeror PUP\n");
			break;
		case ETHERTYPE_SPRITE:
			//printf("Sprite\n");
			break;
		case ETHERTYPE_AT:
			//printf("AppleTalk ARP\n");
			break;
		case ETHERTYPE_AARP:
			//printf("AppleTalk ARP\n");
			break;
		case ETHERTYPE_VLAN:
			//printf("IEEE 802.1Q VLAN tagging\n");
			break;
		case ETHERTYPE_IPX:
			//printf("IPX\n");
			break;
		case ETHERTYPE_IPV6:
			//printf("Ipv6\n");
			break;
		case ETHERTYPE_LOOPBACK:
			//printf("Loopback\n");
			break;
		default:
			//printf("unknown ethertype\n");
			break;
	}
	
	return;
}
