#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdint.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN	6
#define ETHERTYPE_IP 0x0800
	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		uint32_t ip_src;
		uint32_t ip_dst;	 /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_char th_sport[2];	/* source port */
		u_char th_dport[2];	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};
	struct sniff_data {
		u_char datavalue[16];
};

void qwer(unsigned char* str,int a){
        int i;
        printf("%s",str);
	printf("\n");
}
void qwert(unsigned char* str,int a){
        int i;
        for(i=0;i<a;i++){
                printf("%d",str[i]);
		for(i;i<a-1;i)
			printf(":");
	}
        printf("\n");
}

void qwerty(unsigned char* str,int a){
        int i;
	for(i=0;i<a;i++){
        	printf("%x",str[i]);
		for(i;i<a-1;i)
			printf(":");
	}
        printf("\n");
}

int main(int argc, char *argv[]){
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */

	const u_char *packet;		/* The actual packet */


	u_short datalength;
	u_char tcpoff;
	u_char ipoff;
	char ip_dst_str[16];
	char ip_src_str[16];
	struct sniff_ethernet *ethernet;
	struct sniff_ip *ip;
	struct sniff_tcp *tcp;
	struct sniff_data *data;


	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	while(1){
		int asdf;
		asdf = pcap_next_ex(handle,&header,&packet);
		if(asdf == -1)
			break;
		ethernet=(struct sniff_ethernet*)packet;
		printf("ethernet des mac addr : ");
		qwerty((*ethernet).ether_dhost,6);
		printf("ethernet src mac addr : ");
		qwerty((*ethernet).ether_shost,6);
		
	if(ntohs((*ethernet).ether_type)==ETHERTYPE_IP)
	{
		ip=(struct sniff_ip*)(packet+14);
		
		inet_ntop(AF_INET,&(*ip).ip_src,ip_src_str,16);
		inet_ntop(AF_INET,&(*ip).ip_dst,ip_dst_str,16);
		printf("ip src addr : ");
		printf("%s\n",ip_src_str);
		printf("ip des addr : ");
		printf("%s\n",ip_dst_str);
		
		ipoff=(ip->ip_vhl & 0x0F) * 4;


	

		if(ip->ip_p==IPPROTO_TCP)
		{
			tcp=(struct sniff_tcp*)(packet+14+ipoff);
			
			
			printf("src port : ");
			qwert((*tcp).th_sport,2);
			printf("des port : ");
			qwert((*tcp).th_dport,2);
		

			tcpoff=(*tcp).th_offx2;
 			tcpoff = tcpoff >>4;
			tcpoff=tcpoff*4;
			data=(struct sniff_data*)(packet+14+ipoff+tcpoff);
			printf("data value : ");

			datalength=(*ip).ip_len-ipoff-tcpoff;
			if(datalength>0)
			qwer((*data).datavalue,datalength > 16 ? 16 : datalength);
			else 
			printf("no data");

	

			printf("\n");
		}
	}	

		}
	pcap_close(handle);
	return(0);
}
