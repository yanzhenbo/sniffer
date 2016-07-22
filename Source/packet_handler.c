#include "../Include/packet_handler.h"
extern int hex;
extern int statistic;
extern int vivid;
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;
	static double begin_time;
	struct pcap_stat pkt_stat;
	if(1 == count) {
		begin_time = header->ts.tv_sec + (double)(header->ts.tv_usec)/1000000; 
	}
	double relative_time = header->ts.tv_sec + (double)(header->ts.tv_usec)/1000000 - begin_time;
	printf("%-4d", count);
	//printf("\tcaplen: %d", header->caplen);
	printf(" %f ", relative_time);

	pcap_stats((pcap_t *)args, &pkt_stat);
	if(statistic) {
		//printf("\trecv %d\t %f Packet/s", pkt_stat.ps_recv, pkt_stat.ps_recv / (relative_time + 0.000001));
		//printf("\tdrop %d", pkt_stat.ps_drop);
		//printf("\tif drop %d\n", pkt_stat.ps_ifdrop);
	}
	ether_handler(packet, header->caplen);
	count ++;
	if(vivid) {
		printf("\n");
	}
#if 0
	if(hex) {
		print_payload(packet, header->caplen);
	}
#endif
	return;
}
