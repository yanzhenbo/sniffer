vpath %.h Include/
vpath %.c Source/
objects = sniffer.o packet_handler.o ether_handler.o arp_handler.o \
		  ip_handler.o tcp_handler.o udp_handler.o \
		  http_handler.o ftp_handler.o telnet_handler.o \
		  print.o statistic.o

sniffer: $(objects)
	@gcc -o sniffer $(objects) -lpcap;

sniffer.o: sniffer.c
%.o: %.h

.PHONY: clean
clean:
	@rm $(objects)
