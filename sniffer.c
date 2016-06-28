/*
 * sniffer.c
 ****************************************************************************
 * 
 * Example compiler command-line for GCC:
 *   gcc -Wall -o sniffex sniffex.c -lpcap
 * 
 ****************************************************************************
 *
 * Filter expression
 * Expression			Description
 * ----------			-----------
 * ip					Capture all IP packets.
 * tcp					Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */

#define APP_NAME		"sniffer"
#define APP_DESC		"Sniffer packet of ip, tcp, udp, http etc using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2016 IIE"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <time.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes */
 #define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for offset */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* ARP header */
struct sniff_arp {
		u_short ar_hrd;					/* Format of hardware address */
		u_short ar_pro;					/* Format of protocol address */
		u_char ar_hln;					/* Length of hardware address */
		u_char ar_pln;					/* Length of protocol address */
		u_short ar_op;					/* ARP opcode (command) */
#if 0
		u_char ar_sha[ETHER_ADDR_LEN];	/* Sender hardware address */
		struct in_addr ar_sip;				/* Sender IP address */
		u_char ar_tha[ETHER_ADDR_LEN];	/* Target hardware address */
		struct in_addr ar_tip;				/* Target IP address */
#endif
};

/* ICMP Header */
struct sniff_icmp {
		
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_short  th_hl_flags;               /* header length, rsvd, flags */
		#define TH_HL(th)      ((ntohs((th)->th_hl_flags) & 0xf000) >> 12)
        #define TH_FIN  0x0001
        #define TH_SYN  0x0002
        #define TH_RST  0x0004
        #define TH_PUSH 0x0008
        #define TH_ACK  0x0010
        #define TH_URG  0x0020
        #define TH_ECE  0x0040
        #define TH_CWR  0x0080
		#define TH_NS	0x0100
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CWR|TH_NS)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header */
struct sniff_udp {
		u_short uh_sport;				/* source port */
		u_short uh_dport;				/* destination port */
		u_short uh_ulen;				/* udp length */
		u_short uh_checksum;			/* udp checksum */
};

/* HTTP header */
struct sniff_http {

};

/* FTP header */
struct sniff_ftp {

};

/* TELNET header */
struct sniff_telnet {

};

void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_app_banner(void);
void print_app_usage(void);
void print_ether_addr(const u_char *packet);

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void ether_handler(const u_char *packet, int len);
void ip_handler(const u_char *packet, int len);
void tcp_handler(const u_char *packet, int len);
void arp_handler(const u_char *packet, int len);
void rarp_handler(const u_char *packet, int len);
void udp_handler(const u_char *packet, int len);
void http_handler(const u_char *packet, int type, int len); //type == 1 is a request, 2 is a response

/*
 * app name/banner
 */
void print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

	return;
}

/*
 * print help text
 */
void print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

	return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("0x%04x   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

void print_ether_addr(const u_char *ether_addr)
{
	int i = 0;
	for( ; i <ETHER_ADDR_LEN - 1; i++) {
		printf("%02x:", *(ether_addr + i));
	}
	printf("%02x", *(ether_addr + i));
	return;
}
/*
 * dissect/print packet
 */

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;
	static double begin_time;
	struct pcap_stat pkt_stat;
	if(1 == count) {
		begin_time = header->ts.tv_sec + (double)(header->ts.tv_usec)/1000000; 
	}
	double relative_time = header->ts.tv_sec + (double)(header->ts.tv_usec)/1000000 - begin_time;
	printf("\n\nPacket number: %d\tcaplen: %d\tlen: %d\n",count,  header->caplen, header->len);
	printf("relative time: %f\n", relative_time);

	pcap_stats((pcap_t *)args, &pkt_stat);
	printf("pkt recv %d\t %f Packet/s", pkt_stat.ps_recv, pkt_stat.ps_recv / (relative_time + 0.000001));
	printf("\tpkt drop %d", pkt_stat.ps_drop);
	printf("\tpkt if drop %d\n", pkt_stat.ps_ifdrop);

	ether_handler(packet, header->caplen);
	count ++;
	printf("\n");
//	print_payload(packet, header->caplen);
	return;
}

void ether_handler(const u_char *packet, int len)
{
	const struct sniff_ethernet *ethernet;	/* The ethernet header  */
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	len -= SIZE_ETHERNET;
	packet += SIZE_ETHERNET;

	printf("	Ethernet II,Src:");
	print_ether_addr(ethernet->ether_shost);
	printf(", Dst: ");
	print_ether_addr(ethernet->ether_dhost);
	printf(", Type:  ");

	switch(ntohs(ethernet->ether_type)) {
		case ETHERTYPE_IP:
			printf("IP (0x%04x)\n", ETHERTYPE_IP);
			ip_handler(packet, len);
			break;
		case ETHERTYPE_ARP:
			printf("ARP\n");
			arp_handler(packet, len);
			break;
		case ETHERTYPE_REVARP:
			printf("RARP\n");
			rarp_handler(packet, SIZE_ETHERNET);
			break;
		case ETHERTYPE_PUP:
			printf("Xeror PUP\n");
			break;
		case ETHERTYPE_SPRITE:
			printf("Sprite\n");
			break;
		case ETHERTYPE_AT:
			printf("AppleTalk ARP\n");
			break;
		case ETHERTYPE_AARP:
			printf("AppleTalk ARP\n");
			break;
		case ETHERTYPE_VLAN:
			printf("IEEE 802.1Q VLAN tagging\n");
			break;
		case ETHERTYPE_IPX:
			printf("IPX\n");
			break;
		case ETHERTYPE_IPV6:
			printf("Ipv6\n");
			break;
		case ETHERTYPE_LOOPBACK:
			printf("Loopback\n");
			break;
		default:
			printf("unknown ethertype\n");
			break;
	}
	
	return;
}

void ip_handler(const u_char *packet, int len)
{
	
	const struct sniff_ip *ip;				/*The IP header */

	int size_ip;

	ip = (struct sniff_ip*)(packet);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("	* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
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
	printf("	From: %s\n", inet_ntoa(ip->ip_src));
	printf("	  To: %s\n", inet_ntoa(ip->ip_dst));
	packet += size_ip;
	len -= size_ip;
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("	TCP\n");
			tcp_handler(packet, len);
			break;
			case IPPROTO_UDP:
			printf("	UDP\n");
			udp_handler(packet, len);
			break;
		case IPPROTO_IP:
			printf("	Dummy protocol for TCP\n");
			break;
		case IPPROTO_ICMP:
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

void arp_handler(const u_char *packet, int len)
{
	const struct sniff_arp *arp;

	arp = (struct sniff_arp*)(packet);
	printf("	Hardware type: 0x%04x\n", ntohs(arp->ar_hrd));
	printf("	Protocol type: 0x%04x\n", ntohs(arp->ar_pro));
	printf("	Hardware size: %u\n", arp->ar_hln);
	printf("	Protocol size: %u\n", arp->ar_pln);
	printf("	Opcode: %u\n", ntohs(arp->ar_op));
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

void rarp_handler(const u_char *packet, int len)
{
	return;
}

void tcp_handler(const u_char *packet, int len)
{
	const struct sniff_tcp *tcp;

	int size_tcp;
	u_short sport;
	u_short dport;

	tcp = (struct sniff_tcp*)(packet);
	size_tcp = TH_HL(tcp)*4;
	if (size_tcp < 20) {
		printf("	* Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	sport = ntohs(tcp->th_sport);
	dport = ntohs(tcp->th_dport);
	printf("	Src port: %u\n", ntohs(tcp->th_sport));
	printf("	Dst port: %u\n", ntohs(tcp->th_dport));
	printf("	Sequence: %u\n", ntohl(tcp->th_seq));
	printf("	Ack: %u\n", ntohl(tcp->th_ack));
	printf("	Header length: %u bytes\n", TH_HL(tcp)*4);
	printf("	Flags: 0x%03x\n", (ntohs(tcp->th_hl_flags))&TH_FLAGS);
	printf("	Window size: %u\n",ntohs(tcp->th_win));
	printf("	Checksum: 0x%04x\n", ntohs(tcp->th_sum));
	printf("	Urgent pointer: %u\n", ntohs(tcp->th_urp));

	packet += size_tcp;
	len -= size_tcp;

	printf("	len: %d sport: %d dport: %d\n", len, sport, dport);
	if(len <= 0)
		return;
	if(dport == 80) {
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
	else if (sport == 80) {
		if(0 == strncmp(packet, "HTTP", 4)) {
			printf("	HTTP\n");
			http_handler(packet, 2, len);			// response packet
		}
		else {
			printf("	TCP SEGMENT DATA: %d bytes\n", len);
		}
	}
	else {

	}
	return;
}

void udp_handler(const u_char *packet, int len)
{
	const struct sniff_udp *udp;

	int size_udp;
	u_short sport;
	u_short dport;

	size_udp = sizeof(struct sniff_udp);
	udp = (struct sniff_udp*)(packet);
	sport = ntohs(udp->uh_sport);
	dport = ntohs(udp->uh_dport);
	printf("	Src port: %u\n", ntohs(udp->uh_sport));
	printf("	Dst port: %u\n", ntohs(udp->uh_dport));
	printf("	Total length: %u\n", ntohs(udp->uh_ulen));
	printf("	Checksum: 0x%04x\n", ntohs(udp->uh_checksum));

	return;
}

/*
 * if a http packet is divided many parts, 
 * the first is http packet, others are tcp packet
 */
void http_handler(const u_char *packet, int type, int len)
{
	typedef struct {
		int len;
		u_char data[0];
	} buffer;
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
			printf("\t%s\n", line->data);
			packet += len;
			len = 0;
			break;
		}
		else {
			printf("\t%s\\r\\n\n", line->data);
			packet += (i + 2);
			len -= (i + 2);
		}

		if(0 == i){				// the line begin with "\r\n"
			break;
		}
	}
	print_payload(packet, len);

	return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[500] = "\0";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */

	print_app_banner();

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc == 3){
		dev = argv[1];
		strcpy(filter_exp, argv[2]);
	}
	else if (argc > 3) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, packet_handler, (u_char *)handle);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

