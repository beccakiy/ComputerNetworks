#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>

 
#define EHTER_ADDR_LEN 6
 
 
 
/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function. */
 
/*Ethernet     Header*/
struct ethheader{
   u_char  ether_dhost[EHTER_ADDR_LEN];
   u_char  ether_shost[EHTER_ADDR_LEN];
   u_short ether_type;
};
 
/*IP Header*/
 
struct ipheader{
   u_char  ip_vhl;    
   u_char  ip_tos;    
   u_short ip_len;    
   u_short ip_id;     
   u_short ip_off;    
   #define IP_RF 0x8000       
   #define IP_DF 0x4000       
   #define IP_MF 0x2000       
   #define IP_OFFMASK 0x1fff  
   u_char  ip_ttl;    
   u_char  iph_protocol;      
   u_short ip_sum;    
   struct  in_addr ip_src,ip_dst;
};
 
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)
 
/* TCP header */
typedef u_int tcp_seq;
 
struct sniff_tcp {
   u_short th_sport;   /* source port */
   u_short th_dport;   /* destination port */
   tcp_seq th_seq;     /* sequence number */
   tcp_seq th_ack;     /* acknowledgement number */
   u_char th_offx2;   
   #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
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
   u_short th_win;    
   u_short th_sum;    
   u_short th_urp;    
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
  
   const struct ethheader *ether;
   const struct ipheader *ip;
   const struct sniff_tcp *tcp;
   const char *payload;
 
   int size_payload;
   int i;
 
   printf("Got a packet\n");
   //make the ethernet header
   ether =(struct ethheader *)packet;
 
   if(ntohs(ether->ether_type) == 0x800)
   {//ip header offset 
       ip = (struct ipheader *)(packet + sizeof(struct ethheader));
      
       printf("    From: %s\n",inet_ntoa(ip->ip_src));
       printf("    To: %s\n", inet_ntoa(ip->ip_dst));
      //determine the protocol 
       switch(ip->iph_protocol){
           case IPPROTO_TCP:
               printf("    Protocol is TCP\n");
               return;
           case IPPROTO_UDP:
               printf("    Protocol is UDP\n");
           case IPPROTO_ICMP:
               printf("    Protocol is ICMP\n");
           default:
               printf("    Protocol other\n");
       }
   
   //tcp offset
   tcp = (struct sniff_tcp*)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
 
   printf("    Source Port%d\n",ntohs(tcp->th_sport));
   printf("   Dst port: %d\n", ntohs(tcp->th_dport));
 
   payload = (u_char *)packet + sizeof(struct ethheader) + sizeof(struct ipheader) +sizeof(struct sniff_tcp);
   
   size_payload = ntohs(ip->ip_len) - (sizeof(struct ipheader) + sizeof(struct sniff_tcp));
   
    if(size_payload > 0){
        printf("  Payload (%d bytes):\n",size_payload);
            // ascii (if printable) 
        const u_char *ch = payload;
        for(int i=0;i<size_payload;i++){
            if(isprint(*ch))
                printf("%c",*ch);
            else
                printf(".");
            ch++;
        }
    }
   
    return;
}
}
 
 
 
int main(){
   pcap_t *handle;
   char errbuf[PCAP_ERRBUF_SIZE];
   struct bpf_program fp;
   char filter_exp[] = "proto \\TCP and (host 10.0.2.5 and 10.0.2.4) and dst port range 10-100";
   bpf_u_int32 net;
 
 
   // Step 1: Open live pcap session on NIC with name eth3
   //         Students needs to change "eth3" to the name
   //         found on their own machines (using ifconfig).
 
   handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
 
   // Step 2: Compile filter_exp into BPF psuedo-code
 
   pcap_compile(handle, &fp, filter_exp, 0, net);
 
   pcap_setfilter(handle, &fp);
 
   // Step 3: Capture packets
 
   pcap_loop(handle, -1, got_packet, NULL);
   pcap_close(handle);   //Close the handle
   return 0;
}
 
 
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
 

