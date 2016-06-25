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
		u_char ar_sha[ETHER_ADDR_LEN];	/* Sender hardware address */
		struct in_addr ar_sip;				/* Sender IP address */
		u_char ar_tha[ETHER_ADDR_LEN];	/* Target hardware address */
		struct in_addr ar_tip;				/* Target IP address */
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

void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_app_banner(void);
void print_app_usage(void);
void got_ip_packet(const u_char *packet, int iphdr_offset);
void got_tcp_packet(const u_char *packet, int tcphdr_offset);
void print_ether_addr(const u_char *packet);
void got_arp_packet(const u_char *packet, int arphdr_offset);
void got_rarp_packet(const u_char *packet, int rarphdr_offset);

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
	printf("%05d   ", offset);
	
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

void got_eth_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;						/* packet counter */

	/* declare pointers to packet headers  */
	const struct sniff_ethernet *ethernet;	/* The ethernet header  */
	
	printf("\nPacket number %d:\n", count);
	count ++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	printf("	Ethernet II,Src:");
	print_ether_addr(ethernet->ether_shost);
	printf(", Dst: ");
	print_ether_addr(ethernet->ether_dhost);
	printf(", Type:  ");

	switch(ntohs(ethernet->ether_type)) {
		case ETHERTYPE_IP:
			printf("IP\n");
			got_ip_packet(packet, SIZE_ETHERNET);
			break;
		case ETHERTYPE_ARP:
			printf("ARP\n");
			//got_arp_packet(packet, SIZE_ETHERNET);
			break;
		case ETHERTYPE_REVARP:
			printf("RARP\n");
			//got_rarp_packet(packet, SIZE_ETHERNET);
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

void got_ip_packet(const u_char *packet, int iphdr_offset)
{
	
	const struct sniff_ip *ip;				/*The IP header */
	//const struct payload;					/* Packet payload */

	int size_ip;

	ip = (struct sniff_ip*)(packet + iphdr_offset);
	
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
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("	TCP\n");
			got_tcp_packet(packet, iphdr_offset + size_ip);
			break;
		case IPPROTO_UDP:
			printf("	UDP\n");
			break;
		default:
			printf("	unkonwn\n");
			break;
	}
	
	print_payload(packet, ntohs(ip->ip_len) + iphdr_offset);
	return;
}

void got_arp_pakcet(const u_char *packet, int arphdr_offset)
{
/*
	const struct sniff_arp *arp;

	arp = (struct sniff_arp*)(packet + arphdr_offset);
	printf("Hardware type: 0x%04x\n", ntohs(arp->ar_hrd));
	printf("Protocol type: 0x%04x\n", ntohs(arp->ar_pro));
	printf("Hardware size: %u\n", arp->ar_hln);
	printf("Protocol size: %u\n", arp->ar_pln);
	printf("Opcode: %u\n", ntohs(arp->ar_op));
	printf("Sender MAC address: ");
	print_ether_addr(arp->ar_sha);
	printf("\nSender IP address: %s\n", inet_ntoa(arp->ar_sip));
	printf("Target MAC address: ");
	print_ether_addr(arp->ar_tha);
	printf("\nTarget IP address: %s\n", inet_ntoa(arp->ar_tip));
*/
	return;
}

void got_rarp_packet(const u_char *packet, int rarphdr_offset)
{
	return;
}

void got_tcp_packet(const u_char *packet, int tcphdr_offset)
{
	const struct sniff_tcp *tcp;
	const u_char *payload;

	int size_tcp;

	tcp = (struct sniff_tcp*)(packet + tcphdr_offset);
	size_tcp = TH_HL(tcp)*4;
	if (size_tcp < 20) {
		printf("	* Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	printf("	Src port: %u\n", ntohs(tcp->th_sport));
	printf("	Dst port: %u\n", ntohs(tcp->th_dport));
	printf("	Sequence: %u\n", ntohl(tcp->th_seq));
	printf("	Ack: %u\n", ntohl(tcp->th_ack));
	printf("	Header length: %u bytes\n", TH_HL(tcp)*4);
	printf("	Flags: 0x%03x\n", (ntohs(tcp->th_hl_flags))&TH_FLAGS);
	printf("	Window size: %u\n",ntohs(tcp->th_win));
	printf("	Checksum: 0x%04x\n", ntohs(tcp->th_sum));
	printf("	Urgent pointer: %u\n", ntohs(tcp->th_urp));
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
	int num_packets = 30;			/* number of packets to capture */

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
	pcap_loop(handle, num_packets, got_eth_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

