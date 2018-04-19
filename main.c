#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define APP_NAME "rewrite-ip"
#define APP_VERSION "0.1"

#ifndef MAX_SIZE
	#define MAX_SIZE 256
#endif 

#ifndef ETHER_ADDR_LEN
	#define ETHER_ADDR_LEN	6
#endif 

#ifndef IP4_ADDR_LEN
	#define IP4_ADDR_LEN	4
#endif 

#define PROTO_TCP 6
#define PROTO_UDP 17

/* Ethernet header */
struct sniff_ethernet {
	uint8_t     ether_dhost[ETHER_ADDR_LEN];  /* Destination host address */
	uint8_t     ether_shost[ETHER_ADDR_LEN];  /* Source host address */
	uint16_t    ether_type;                  /* IP? ARP? RARP? etc */
};

#ifndef ETHER_HEADER_SIZE
	#define ETHER_HEADER_SIZE 14
#endif 

#ifndef IP4_HEADER_SIZE
	#define IP4_HEADER_SIZE 20
#endif

static struct in_addr in_addr_ip_in;
static struct in_addr in_addr_ip_out;

/* IP header */
struct sniff_ip {
	uint8_t         ip_vhl;		/* version << 4 | header length >> 2 */
	uint8_t         ip_tos;		/* type of service */
	uint16_t        ip_len;		/* total length */
	uint16_t        ip_id;		/* identification */
	uint16_t        ip_off;		/* fragment offset field */
#define IP_RF 0x8000		    /* reserved fragment flag */
#define IP_DF 0x4000		    /* dont fragment flag */
#define IP_MF 0x2000		    /* more fragments flag */
#define IP_OFFMASK 0x1fff	    /* mask for fragmenting bits */
	uint8_t         ip_ttl;		/* time to live */
	uint8_t         ip_p;		/* protocol */
	uint16_t        ip_sum;		/* checksum */
	struct in_addr  ip_src;     /* source and dest address */
	struct in_addr  ip_dst;     /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* IPv6 header */
struct sniff_ip6 {
	uint8_t     ip_vtc;         /* version << 4 | traffic_class msb >> 4*/
	uint8_t     ip_tcfl;        /* traffic_class lsb << 4 | flow_label msb >> 4*/
	uint16_t    ip_flow_label;  /* traffic_class lsb << 4 | flow_label msb >> 4*/
	uint16_t    payload_len;
	uint8_t     next_header;
	uint8_t     hop_limit;
	uint32_t    src_addr[4];
	uint32_t    dst_addr[4];	
};

/* TCP header */
struct sniff_tcp {
    uint16_t    th_sport;       /* source port */
    uint16_t    th_dport;       /* destination port */
    uint32_t    th_seq;         /* sequence number */
    uint32_t    th_ack;         /* acknowledgement number */
    uint8_t     th_offx2;       /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    uint8_t     th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    uint16_t    th_win;          /* window */
    uint16_t    th_sum;          /* checksum */
    uint16_t    th_urp;          /* urgent pointer */
};

void usage()
{
    printf ("%s modifies a specific IP address in a PCAP to another one\n", APP_NAME );
	printf( "Usage :\n\t%s <incap> <IP to change> <IP new value>\n", APP_NAME);
}

void printmac(const uint8_t *eth)
{
	uint8_t i = 0;
	for( i = 0; i < ETHER_ADDR_LEN; i++ )
	{
		printf( "%02x", eth[i] );
		if( i != (ETHER_ADDR_LEN-1) )
		{
			printf(":");
		}
	}
}

void printip(const struct in_addr *ip)
{
	printf( "%s", inet_ntoa(*ip) );
}

static char pcap_in[MAX_SIZE] = "";
static char pcap_out[MAX_SIZE] = "";
static char errbuff[PCAP_ERRBUF_SIZE] = "";

/*
 * Calculate the new TCP checksum after IP address rewrite
 */ 
uint16_t tcp_sum_calc(uint16_t len_tcp, uint16_t src_addr[],uint16_t dest_addr[], uint16_t buff[])
{
	uint16_t padd=0;
	uint16_t i = 0;
	uint32_t checksum = 0;
	struct sniff_tcp *tcp_header = (struct sniff_tcp*)buff;
	
	// Find out if the length of data is even or odd number. If odd,
	// add a padding byte = 0 at the end of packet
	if ( 1 == ( len_tcp & 1 ) )
	{
		printf( "Need Pad\n" );
		padd=1;
		buff[len_tcp]=0;
	}
		
	for( i=0; i< (len_tcp+padd)/sizeof(uint16_t); i++ )
	{
		checksum += ntohs(*(buff+i));		
	}	

	checksum -= ntohs(tcp_header->th_sum);
	checksum += ntohs(src_addr[0]);
	checksum += ntohs(src_addr[1]); 
	checksum += ntohs(dest_addr[0]); 
	checksum += ntohs(dest_addr[1]); 
	
	// the protocol number and the length of the TCP packet
	checksum = checksum + IPPROTO_TCP + len_tcp;

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
	while (checksum>>16)
		checksum = (checksum & 0xFFFF)+(checksum >> 16);
		
	// Take the one's complement of sum
	checksum = ~checksum;
	return (uint16_t)checksum;
}

/*
 * Calculate the new IP checksum after IP address rewrite
 */ 
uint16_t ip_header_checksum(struct sniff_ip* iph)
{
	uint16_t *ptr = (uint16_t*)iph;
	uint16_t i = 0;
	uint32_t checksum = 0;
	uint32_t carry = 0;
	for( i = 0; i < IP4_HEADER_SIZE/2; i++ )
	{
		checksum += ntohs(*(ptr+i));
	}
	checksum -= ntohs(iph->ip_sum);
	if( 0xFFFF <= checksum )
	{
		carry = ( checksum & 0xF0000 ) >> 16;
		checksum = (checksum & 0xFFFF) + carry;
		checksum = (checksum ^ 0xFFFF);
	}
	else if( 0xFFFF > checksum )
	{
		carry = ( checksum & 0xF000 ) >> 12;
		checksum = (checksum & 0xFFF) + carry;
		checksum = (checksum ^ 0xFFF);		
	}
	return checksum;
}

int32_t main(int argc, char **argv )
{
	if( 1 == argc )
	{
		usage();
		exit(-1);
	}
	
	strcpy( pcap_in, argv[1] );

	printf( "Reading %s\n", pcap_in );
	pcap_t *pcap = pcap_open_offline(pcap_in, errbuff);
	if( NULL == pcap )
	{
		perror( "pcap_open_offline" );
		exit(-2);
	}

	printf( "Replacing %s by %s\n", argv[2], argv[3] );
	inet_aton(argv[2], &in_addr_ip_in);
	inet_aton(argv[3], &in_addr_ip_out);

	sprintf( pcap_out, "output.cap");
	pcap_t* pd = pcap_open_dead(DLT_EN10MB, 65535);
	pcap_dumper_t* pdumper = pcap_dump_open(pd, pcap_out);
	if( NULL == pdumper )
	{
		perror( "pcap_dump_open" );
	}
	
	struct pcap_pkthdr *header = NULL;
	const uint8_t *data = NULL;
	int32_t ret = 0;

	do
	{
		ret = pcap_next_ex(pcap, &header, &data);
		if( 0 > ret )
		{
			break;
		}

		struct sniff_ip *ip_header = (struct sniff_ip*)(data+ETHER_HEADER_SIZE);
		if( 0 == memcmp(&ip_header->ip_src, &in_addr_ip_in, sizeof(struct in_addr) ) )
		{
			memcpy(&ip_header->ip_src, &in_addr_ip_out, sizeof(struct in_addr) );
			uint16_t checksum = ip_header_checksum(ip_header);
			ip_header->ip_sum = htons(checksum);
		}
		else if( 0 == memcmp(&ip_header->ip_dst, &in_addr_ip_in, sizeof(struct in_addr) ) )
		{
			memcpy(&ip_header->ip_dst, &in_addr_ip_out, sizeof(struct in_addr) );
			uint16_t checksum = ip_header_checksum(ip_header);
			ip_header->ip_sum = htons(checksum);
		}
		
		if( IPPROTO_TCP == ip_header->ip_p )
		{
			uint16_t tcp_packet[9000];
			struct sniff_tcp *tcp_header = (struct sniff_tcp*)(data + ETHER_HEADER_SIZE + IP4_HEADER_SIZE );

			uint16_t tcp_len = ntohs(ip_header->ip_len) - IP4_HEADER_SIZE;
			memcpy( tcp_packet, (uint16_t*)(data + ETHER_HEADER_SIZE + IP4_HEADER_SIZE ), tcp_len );
			uint16_t checksum = tcp_sum_calc(tcp_len, (uint16_t*)&ip_header->ip_src, (uint16_t*)&ip_header->ip_dst, tcp_packet );
			tcp_header->th_sum = htons(checksum);
		}
		pcap_dump((uint8_t*)pdumper, header, (const uint8_t*)data);

	} while( 0 <= ret );

	pcap_close( pcap );
	pcap_dump_close( pdumper );
	return 0;
}
