CC := clang

ifeq ($(DEBUG),1)
	CFLAGS :=  -O0 -g
else
	CFLAGS :=  -O1 
endif

LDFLAGS := -lpcap -ljson-c 

run: hash_pcap.o
	$(CC) -o run hash_pcap.o $(LDFLAGS)
hash_pcap.o: hash_pcap.c
	$(CC) $(CFLAGS) -c hash_pcap.c $(LDFLAGS)

clear:
	rm  -f *.o run *csv
	
