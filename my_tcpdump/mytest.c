#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

/*grab the first packet with libpcap*/
int main()
{
  int i;
  char *dev;
  bpf_u_int32 mask;
  bpf_u_int32 net;
  struct in_addr addr;
  char *net_addr;
  char *mask_addr;
  pcap_t *handle;
  struct pcap_pkthdr header;
  const u_char *packet;
  struct ether_header *eptr;
  u_char * ptr;/*point to the MAC address*/
  /*
    struct ether_header
    {
    u_int8_t ether_dhost[ETH_ALEN];//destination eth addr
    u_int8_t ether_shost[ETH_ALEN];//ETH_ALEN=6
    u_int16_t ether_type;//packet type ID field
    };
   */
  char errbuf[PCAP_ERRBUF_SIZE];

  dev=pcap_lookupdev(errbuf);
  if(dev==NULL){
    fprintf(stderr,"Could not find default device: %s\n",dev);
    exit(1);
  }
  printf("Dev: %s\n",dev);

  if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1){
    fprintf(stderr,"could not get netmask for device %s\n",dev);
    exit(1);
    }
  
  addr.s_addr=net;
  net_addr=inet_ntoa(addr);
  printf("Net: %s\n",net_addr);

  addr.s_addr=mask;
  mask_addr=inet_ntoa(addr);
  printf("Mask: %s\n",mask_addr);


  handle=pcap_open_live(dev,BUFSIZ,-1,1000,errbuf);
  if(handle==NULL){
    fprintf(stderr,"could not open device %s\n",dev);
    exit(1);
  }

  /*
  //set the filter
  if(pcap_compile(handle,&fp,filter_exp,0,mask)==-1){
    fprintf(stderr,"could not parser filter %s: %s\n",filter_exp,pcap_geterr(handle));
    exit(1);
  }
  if(pcap_setfilter(handle,&fp)==-1){
    fprintf(stderr,"could not install filter %s: %s\n",filter_exp,pcap_geterr(handle));
    exit(1);
    }*/

  packet=pcap_next(handle,&header);
  if(packet!=NULL){
  printf("Grabbed packet of length %d\n",header.len);
  printf("Grabbed packet at ... %s\n",ctime((const time_t *)&header.ts.tv_sec));
  
  /*lets start with the ether header*/
  printf("Ethernet header length is %d\n",ETHER_HDR_LEN);
  printf("Ehternet address length is %d\n",ETHER_ADDR_LEN);
  eptr=(struct ether_header *)packet;
  if(ntohs(eptr->ether_type)==ETHERTYPE_IP){
    printf("Ethernet type hex:%x dec:%d is an IP packet\n",ntohs(eptr->ether_type),ntohs(eptr->ether_type));
  }else if(ntohs(eptr->ether_type)==ETHERTYPE_ARP){
    printf("Ethernet type hex:%x dec:%d is an ARP packet\n",ntohs(eptr->ether_type),ntohs(eptr->ether_type));
  }else{
    printf("Ethernet type hex:%x not IP\n",ntohs(eptr->ether_type));
    exit(1);
  }
  ptr=eptr->ether_dhost;
  i=ETH_ALEN;
  printf("Destination Address: ");
  do{
    printf("%s%x",(i==ETH_ALEN)?" ":":",*ptr++);
  }while(--i>0);

  printf("\n");
  ptr=eptr->ether_shost;
  i=ETH_ALEN;
  printf("Source Address: ");
  do{
    printf("%s%x",(i==ETH_ALEN)?" ":":",*ptr++);
  }while(--i>0);
  }else{
    printf ("NULL\n");
  }

  printf("\n");
  
  pcap_close(handle);

  exit(0);
}
