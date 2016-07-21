#include "../Include/tcp_handler.h"
extern int vivid;
extern int proto[PROTO_CATEGORY];
void tcp_handler(const u_char *packet, int len)
{
	const struct sniff_tcp *tcp;

	int size_tcp;
	u_short sport;
	u_short dport;
	u_short flags;
	tcp = (struct sniff_tcp*)(packet);
	size_tcp = TH_HL(tcp)*4;
	if (size_tcp < 20) {
		printf("	* Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	printf("\tTCP\t");
	sport = ntohs(tcp->th_sport);
	dport = ntohs(tcp->th_dport);
	flags = (ntohs(tcp->th_hl_flags))&TH_FLAGS;
	if(flags&TH_FIN) printf("\tFIN");
	if(flags&TH_SYN) printf("\tSYN");
	if(flags&TH_RST) printf("\tRST");
	if(flags&TH_PUSH) printf("\tPSH");
	if(flags&TH_ACK) printf("\tACK");
	if(flags&TH_URG) printf("\tURG");  
	if(flags&TH_ECE) printf("\tECE");
	if(flags&TH_CWR) printf("\tCWR");
	if(flags&TH_NS)  printf("\tNS");
	printf("\n");
	if(vivid) {
		printf("	Src port: %u\n", ntohs(tcp->th_sport));
		printf("	Dst port: %u\n", ntohs(tcp->th_dport));
		printf("	Sequence: %u\n", ntohl(tcp->th_seq));
		printf("	Ack: %u\n", ntohl(tcp->th_ack));
		printf("	Header length: %u bytes\n", TH_HL(tcp)*4);
		printf("	Flags: 0x%03x\n", (ntohs(tcp->th_hl_flags))&TH_FLAGS);
		printf("	Window size: %u\n",ntohs(tcp->th_win));
		printf("	Checksum: 0x%04x\n", ntohs(tcp->th_sum));
		printf("	Urgent pointer: %u\n", ntohs(tcp->th_urp));
	}
	packet += size_tcp;
	len -= size_tcp;

	printf("	App layer len: %d\n", len);
	if(len <= 0)
		return;
	if(80 == dport || 80 == sport) {
		proto[HTTP_INDEX] ++;
		if(80 == dport) {
			/*
			 * if the first few letters meet the following requirement, 
			 * it is a http packet.
			*/
			if(0 == strncmp(packet,"GET", 3)	 || 0 == strncmp(packet, "POST", 4)   ||
			   0 == strncmp(packet, "HEAD", 4)	 || 0 == strncmp(packet, "OPTION", 6) ||
			   0 == strncmp(packet, "PUT", 3)	 || 0 == strncmp(packet, "DELETE", 6) ||
			   0 == strncmp(packet, "TRACE", 5)  || 0 == strncmp(packet, "CONNECT", 7)) {
				printf("	HTTP\n");
				http_handler(packet, 1, len);			// request packet
			}
			else {
				printf("	TCP SEGMENT DATA: %d bytes\n", len);
			}
		}
		else if (80 == sport) {
			if(0 == strncmp(packet, "HTTP", 4)) {
				printf("	HTTP\n");
				http_handler(packet, 2, len);			// response packet
			}
			else {
				printf("	TCP SEGMENT DATA: %d bytes\n", len);
			}
		}
	}
	else if(20 == dport || 20 == sport) {
		proto[FTP_INDEX] ++;
		ftp_handler(packet, 2, len);
	}
	else if(21 == dport || 21 == sport) {
		proto[FTP_INDEX] ++;
		ftp_handler(packet, 1, len);
	}
	else if(23 == dport || 23 == sport) {
		proto[TELNET_INDEX] ++;
		telnet_handler(packet, len);
	}
	else if(502 == dport || 502 == sport) {
		proto[MODBUS_INDEX] ++;
		modbus_handler(packet, len);	
	}

	return;
}
