#include "mypcap.h"

typedef union{
  unsigned char str[2];
  unsigned short value;
}endian;

int test_endian(){
  endian test;
  test.value=0x5001;
  if(test.str[0]==0x01 && test.str[1]==0x50)
    return 1;//little-endian
  else
    return 0;//big-endian
}

/*handle ethernet layer header*/
u_int16_t get_packet_type(const u_char *packet){
  struct ether_header *ethheader;
  
  ethheader=(struct ether_header *)packet;
  u_char *ptr;
  int i;
  u_int16_t type;

  ptr=ethheader->ether_dhost;
  printf("Destination MAC: ");
  for(i=ETH_ALEN;i>0;i--)
    printf("%s%x",(i==ETH_ALEN)?" ":":",*ptr++);
  printf(" >>> ");
  ptr=ethheader->ether_shost;
  printf("Source MAC: ");
  for(i=ETH_ALEN;i>0;i--)
    printf("%s%x",(i==ETH_ALEN)?" ":":",*ptr++);
  printf("  ");
  
  /*printf("Destion MAC: %s\n",ether_ntoa(ethheader->ether_dhost));
    printf("Source MAC: %s\n",ether_ntoa(ethheader->ether_shost));*/

  type=ntohs(ethheader->ether_type);
  if(type==0x0800){
    return ETHERTYPE_IP;
  }else if(type==0x0806){
    return ETHERTYPE_ARP;
  }else{
    return 0x0000;
  }
}


void handler_TCP(const u_char *packet,int ih_len){
  //printf("Here we analyze the TCP partion\n");
  struct tcphdr *tcp;
  tcp=(struct tcphdr *)(packet+sizeof(struct ether_header)+ih_len);
  printf("dll and ip layers header length: %d\n",sizeof(struct ether_header)+ih_len);
  printf("sport: %u ->\t",htons(tcp->source));
  printf("dport: %u\t",htons(tcp->dest));
  printf("seq: 0x%x\t",htonl(tcp->seq));
  printf("ack-seq: 0x%x\t",htonl(tcp->ack_seq));
  printf("window_size: %u\n",htons(tcp->window));
  
}

void handler_UDP(const struct iphdr *ip,int ih_len){
  printf("Here we analyze the UDP partion\n");
}

void handler_IP(const struct pcap_pkthdr *header,const u_char *packet){
  
  //printf("  Here we analyze the IP partion  ");
  const struct iphdr *ip;
  ip=(struct iphdr *)(packet+sizeof(struct ether_header));
  if(ip->version==4){
    printf("  ipV4  ");
    printf("total_len: %u  ",htons(ip->tot_len));
    int ih_len=ip->ihl*4;
    printf("ip_header_len: %d  ",ih_len);
    printf("id: %d  ",htons(ip->id));
    char buf[64];
    inet_ntop(AF_INET,&ip->saddr,buf,64);
    printf("%s >>>",buf);
    buf[0]='\0';
    inet_ntop(AF_INET,&ip->daddr,buf,64);
    printf("%s  ",buf);
    printf("%d\n",ip->protocol);
    if(ip->protocol==6){
      handler_TCP(packet,ih_len);
    }else if(ip->protocol==17){
      handler_UDP(ip,ih_len);
    }

  }
}

void handler_ARP(const u_char *packet){
  //fprintf(stdout,"Here we analyze the ARP partion\n");
  struct arphdr *arp;
  struct ether_arp *arp_addr;
  arp=(struct arphdr *)(packet+sizeof(struct ether_header));
  arp_addr=(struct ehter_arp *)(packet+14);
  printf("sender hardware address: %s\n",ether_ntoa((struct ether_addr *)arp_addr->arp_sha));
  printf("target hardware address: %s\n",ether_ntoa((struct ether_addr *)arp_addr->arp_tpa));
  char buf[64];
  inet_ntop(AF_INET,&arp_addr->arp_spa,buf,64);
  printf("sender protocol address: %s\n",buf);
  buf[0]='\0';
  inet_ntop(AF_INET,&arp_addr->arp_tpa,buf,64);
  printf("target protocol address: %s\n",buf);
 
  printf("Format of hardware address: %d  ",arp->ar_hrd);
  printf("Format of protocol address: %d\n",arp->ar_pro);
  
  
}

void handler_RARP(){
  fprintf(stdout,"Here we analyze the RARP partion\n");
}

void handler_UNKNOWN(){
  fprintf(stdout,"Here we analyze UNKNOWN partion\n");
}

void my_callback(u_char *user,const struct pcap_pkthdr *header,const u_char *packet){

  u_int16_t type=get_packet_type(packet);

  struct pcap_pkthdr tmpheader=*header;
  if(packet!=NULL){
    //printf("%s    ",ctime((const time_t *)&tmpheader.ts.tv_sec));
    printf("length %d\n",tmpheader.len);
  }
  
  if(type==ETHERTYPE_IP){
    handler_IP(header,packet);
    printf("\n");
  }else if(type==ETHERTYPE_ARP){
    handler_ARP(packet);
    printf("\n");
  }else{
    handler_UNKNOWN();
    printf("\n");
    }

}


int main(int argc,char **argv){
  /*main function*/
  
  char *dev;
  char *mask;
  char *net;
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netcode;
  bpf_u_int32 maskcode;
  struct in_addr addr;
  pcap_t *handler;
  struct bpf_program fp;
  struct pcap_pkthdr *header;
  const u_char * packet;
  u_char *args;

  if(argc<2){
    fprintf(stdout,"Usage: filter \"expression\"\n");
    exit(1);
  }

  if( (dev=pcap_lookupdev(errbuf))==NULL){
    fprintf(stdout,"%s\n",errbuf);
    exit(1);
  }

  if( pcap_lookupnet(dev,&netcode,&maskcode,errbuf)<0){
    fprintf(stdout,"%s\n",errbuf);
    exit(1);
  }

  /*print netcard info*/
  printf("Dev: %s\n",dev);
  addr.s_addr=netcode;
  net=inet_ntoa(addr);
  printf("Net: %s\n",net);
  addr.s_addr=maskcode;
  mask=inet_ntoa(addr);
  printf("Mask: %s\n",mask);
  
  if( (handler=pcap_open_live(dev,BUFSIZ,0,1000,errbuf))==NULL){
    fprintf(stdout,"%s\n",errbuf);
    exit(1);
  }

  /*set packet filter*/
  if(argc==2){
    if( pcap_compile(handler,&fp,argv[1],0,maskcode)<0){
      fprintf(stdout,"%s\n",pcap_geterr(handler));
      exit(1);
    }
    if( pcap_setfilter(handler,&fp)<0){
      fprintf(stdout,"%s\n",pcap_geterr(handler));
      exit(1);
    }
   }

  if(argc==2){
    if( pcap_loop(handler,-1,(pcap_handler)my_callback,args)<0){
      fprintf(stdout,"%s\n",pcap_geterr(handler));
      exit(1);
    }
  }else{
    if( pcap_loop(handler,atoi(argv[1]),(pcap_handler)my_callback,args)<0){
      fprintf(stdout,"%s\n",pcap_geterr(handler));
      exit(1);
    }
  }

  exit(0);
}
