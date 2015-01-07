#include "mypcap.h"

void my_callback(u_char *useless,struct pcap_pkthdr *header,const u_char *packet){
  static int count=1;
  fprintf(stdout,"%d ",count);
  if(count==4){
    fprintf(stdout,"Come on baby,I have received 4 packets");
  }
 if(count==7){
    fprintf(stdout,"Come on baby,I have received 7 packets");
  }

 fflush(stdout);
 count++;
}

int main(int argc,char **argv)
{
  if(argc !=2){
    fprintf(stdout,"Usage: \"filter condition\"\n");
    exit(1);
    }
  
  char errbuf[PCAP_ERRBUF_SIZE];
  char *dev;
  bpf_u_int32 net;
  bpf_u_int32 mask;
  pcap_t * handler;
  //char filter[]="port 80";
  struct bpf_program fp;
  
  if( (dev=pcap_lookupdev(errbuf))==NULL){
    fprintf(stdout,"%s\n",errbuf);
    exit(1);
  }

  if( pcap_lookupnet(dev,&net,&mask,errbuf)==-1){
    fprintf(stdout,"%s\n",errbuf);
    exit(1);
  }

  if ( (handler=pcap_open_live(dev,BUFSIZ,0,100,errbuf))==NULL){
    fprintf(stdout,"%s\n",errbuf);
  }
  
  if( pcap_compile(handler,&fp,argv[1],0,mask)<0){
    fprintf(stdout,"%s\n",pcap_geterr(handler));
    exit(1);
  }
  if( pcap_setfilter(handler,&fp)<0){
    fprintf(stdout,"%s\n",pcap_geterr(handler));
    exit(1);
  }

  if( pcap_loop(handler,-1,(pcap_handler)my_callback,NULL)==-1){
    fprintf(stdout,"%s\n",pcap_geterr(handler));
    exit(1);
  }

  fprintf(stdout,"packets grabbing finished\n");

  exit(0);
}
  
  
