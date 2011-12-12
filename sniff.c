#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h> 

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* 
	packet) 
{ 
	static int count = 1; 
	fprintf(stdout, "%3d, ", count);
	fflush(stdout);
	count++; 
}

void another_callback(u_char *arg, const struct pcap_pkthdr* pkthdr, 
		const u_char* packet) 
{ 
	int i=0; 
	static int count=0; 

	printf("Packet Count: %d\n", ++count);	/* Number of Packets */
	printf("Recieved Packet Size: %d\n", pkthdr->len);	/* Length of header */
	printf("Payload:\n"); 				/* And now the data */
	for(i=0;i<pkthdr->len;i++) { 
		if(isprint(packet[i]))			/* Check if the packet data is printable */
			printf("%c ",packet[i]); 	/* Print it */
		else 
			printf(" . ",packet[i]);		/* If not print a . */
		if((i%16==0 && i!=0) || i==pkthdr->len-1) 
			printf("\n"); 
	}
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	
	static int count = 0;
	printf("Packet Count: %d\n", ++count);  /* Number of Packets */
        printf("Recieved Packet Size: %d\n\n", header->len);      /* Length of header */
        /* save the packet on the dump file */
        pcap_dump(dumpfile, header, pkt_data);
}

int main(int argc,char **argv) 
{ 
	int i;
	int devid;
	int returnvalue;
	pcap_if_t* alldevsp; 
	pcap_if_t* t;
	char* defaultdev = "ppp0";
	char* dev;
	char errbuf[PCAP_ERRBUF_SIZE]; 
	pcap_t* handle; 
	pcap_dumper_t *dumpfile;
	const u_char *packet; 
	struct pcap_pkthdr hdr;
	struct ether_header *eptr;	/*  net/ethernet.h      */ 
	struct bpf_program fp;	/* hold compiled program   */ 
	bpf_u_int32 maskp;		/* subnet mask        */ 
	bpf_u_int32 netp;		/* ip            */ 
	struct in_addr addr;

	if(argc != 3){
		fprintf(stdout, "Usage: %s \"expression\"\n" 
			,argv[0]);
		return 0;
	} 

	/* Now get a device */
	returnvalue = pcap_findalldevs(&alldevsp,errbuf); 
	
	if(returnvalue == -1) {
		fprintf(stderr, "%s\n", errbuf);
		exit(1);
	} 
	else{
		printf("\nList of detected devices");
		for(t = alldevsp, i = 0; t != NULL; t= t->next){
			printf("\n\t%d. %s", ++i, t->name);
		}
	}
	printf("\nSelect that you need to monitor (1-%d) :",i);
	scanf("%d",&devid);
	for(t = alldevsp, i = 0; i < devid - 1; t= t->next,i++);
	printf("\n\tCapturing packets on interface : %s \n",t->name);
	strcpy(dev,t->name);
	
	/* Get the network address and mask */ 
	pcap_lookupnet(dev, &netp, &maskp, errbuf); 

	addr.s_addr = netp;
	printf("NET: %s\n",inet_ntoa(addr));
	addr.s_addr = maskp;
	printf("MASK: %s\n",inet_ntoa(addr));

	/* open device for reading in promiscuous mode */ 
	handle = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf); 
	if(handle == NULL) {
		printf("pcap_open_live(): %s\n", errbuf);
		exit(1);
	} 

	/* Now we'll compile the filter expression*/ 
	if(pcap_compile(handle, &fp, argv[1], 0, netp) == -1) {
		fprintf(stderr, "Error calling pcap_compile\n");
		exit(1);
	} 

	/* set the filter */ 
	if(pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Error setting filter\n");
		exit(1);
	} 
        
	/* Open the dump file */
        dumpfile = pcap_dump_open(handle, argv[2]);
        if(dumpfile==NULL)
        {
        	fprintf(stderr,"\nError opening output file\n");
	        exit(1);
    	}
	
	/* loop for callback function */ 
//	pcap_loop(handle, -1, another_callback, NULL);
	pcap_loop(handle, 0, packet_handler, (unsigned char *)dumpfile); 
	pcap_close(handle);
	return 0; 
}

