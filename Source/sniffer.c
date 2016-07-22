/* 
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

#include "../Include/print.h"
#include "../Include/packet_handler.h"
#include "../Include/statistic.h"
#include <pcap.h>	/* pcap_t, PCAP_ERRBUF_SIZE, */
#include <pcap/bpf.h>	/* bpf_u_int32, struct bpf_program*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h> /*u_int, u_char etc. */
#include <getopt.h>
#include <unistd.h>
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

int vivid = 0;
int hex = 0;
int statistic = 0;

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char *filter_exp = NULL;		/* filter expression */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */
    
	/* dev initiaized */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}

	struct option long_options[] = {
		{"interface", required_argument, NULL, 'i'},
		{"count", required_argument, NULL, 'c'},
		{"filter", required_argument, NULL,	'f'},
		{"help", no_argument, NULL, '?'},
		{"vivid", no_argument, NULL, 'v'},
		{"statistic", no_argument, NULL, 's'},
		{NULL, 0, NULL, 0}
	};
	int opt = 0;
	int options_index = 0;
	char *tmp = NULL;
    while((opt=getopt_long(argc, argv, "sxvi:c:f:?h", long_options, &options_index)) != EOF) {
		switch(opt) {
			case   0: break;
			case 's':
				statistic = 1;
				break;
			case 'x':
				hex = 1;
				break;
			case 'v':
				vivid = 1;
				break;
			case 'i': 
				dev = optarg;
				break;
			case 'c':
				num_packets = atoi(optarg);
				break;
			case 'f':
				filter_exp = optarg;
				break;
			case '?':
			case 'h':
				print_app_usage();
				exit(EXIT_FAILURE);
			default:
				break;
		}
	}

	//print_app_banner();
	if (argc == 1) {
		print_app_usage();
		exit(EXIT_FAILURE);
	}
		
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	//printf("Device: %s\n", dev);
	//printf("Number of packets: %d\n", num_packets);
	//printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device */
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

	printf("\n\tCapture complete.\n");

	if(statistic) {
		proto_stat_print();
	}
	return 0;
}

