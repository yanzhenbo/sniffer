#include "../Include/ip_handler.h"
extern int vivid;
extern int proto[PROTO_CATEGORY];
void ip_handler(const u_char *packet, int len)
{
	
	const struct sniff_ip *ip;				/*The IP header */

	int size_ip;
	u_short ip_len;
	
	printf("IP ");
	if(vivid) {
		printf("\n");
	}
	ip = (struct sniff_ip*)(packet);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("	* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	ip_len = ntohs(ip->ip_len);
	if(vivid) {
		printf("	Version: %u\n", IP_V(ip));
	    printf("	header length: %u bytes\n", IP_HL(ip)*4);
     	printf("	Tos: 0x%02x\n", ip->ip_tos);
    	printf("	Total length: %u\n", ntohs(ip->ip_len));
    	printf("	Identification: 0x%04x (%u)\n", ntohs(ip->ip_id), ntohs(ip->ip_id));
    	printf("	Flags: 0x%02x\n",((ntohs(ip->ip_off))&(IP_RF|IP_DF|IP_MF))>>13);
    	printf("	Fragment offset: %d\n", (ntohs(ip->ip_off))&IP_OFFMASK);
	    printf("	Time to live: %u\n", ip->ip_ttl);
    	printf("	Protocal: %u\n", ip->ip_p);
    	printf("	Header checksum: 0x%04x\n", ntohs(ip->ip_sum));
	}
	if(vivid) {
		printf("\t");
	}
	printf("From: %s", inet_ntoa(ip->ip_src));
	printf(" To: %s ", inet_ntoa(ip->ip_dst));
	packet += size_ip;
	len = ip_len - size_ip;
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			proto[TCP_INDEX] ++;
			tcp_handler(packet, len);
			break;
		case IPPROTO_UDP:
			proto[UDP_INDEX] ++;
			udp_handler(packet, len);
			break;
		case IPPROTO_IP:
			printf("	Dummy protocol for TCP\n");
			break;
		case IPPROTO_ICMP:
			proto[ICMP_INDEX] ++;
			printf("	ICMP\n");
			break;
		case IPPROTO_IGMP:
			printf("	IGMP\n");
			break;
		case IPPROTO_IPIP:
			printf("	IPIP tunnels\n");
			break;
		case IPPROTO_EGP:
			printf("	EGP\n");
			break;
		case IPPROTO_PUP:
			printf("	PUP\n");
			break;
		case IPPROTO_IDP:
			printf("	IDP\n");
			break;
		case IPPROTO_TP:
			printf("	TP\n");
			break;
		case IPPROTO_DCCP:
			printf("	DCCP\n");
			break;
		case IPPROTO_IPV6:
			printf("	IPV6\n");
			break;
		case IPPROTO_RSVP:
			printf("	RSVP\n");
			break;
		case IPPROTO_GRE:
			printf("	GRE\n");
			break;
		case IPPROTO_ESP:
			printf("	ESP\n");
			break;
		case IPPROTO_AH:
			printf("	AH\n");
			break;
		case IPPROTO_MTP:
			printf("	MTP\n");
			break;
		case IPPROTO_BEETPH:
			printf("	BEETPH\n");
			break;
		case IPPROTO_ENCAP:
			printf("	ENCAP\n");
			break;
		case IPPROTO_PIM:
			printf("	PIM\n");
			break;
		case IPPROTO_COMP:
			printf("	COMP\n");
			break;
		case IPPROTO_SCTP:
			printf("	SCTP\n");
			break;
		case IPPROTO_UDPLITE:
			printf("	UDPLITE\n");
			break;
		case IPPROTO_RAW:
			printf("	Raw IP pakcet\n");
			break;
		default:
			printf("	unkonwn\n");
			break;
	}
	
	return;
}
