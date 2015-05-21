#include "ping.h"

struct proto proto_v4={
	proc_v4,send_v4,NULL,NULL,NULL,0,IPPROTO_ICMP};

struct addrinfo * host_serv(const char *);//get addrinfo of argv[1]
char ip[32];
char * gethost(struct sockaddr *,size_t);//get the ip(6) address

int datalen=56;//data after icmp 8 byte header including timestamp

int main(int argc,char *argv[]){

	struct addrinfo *ai;
	char *h;
	
	if(argc!=2){
		printf("Usage ./my_ping <Host|DomainName>\n");
		exit(1);
	}

	host=argv[1];
	pid=getpid()&0xffff;//16 bit
	
	if(signal(SIGALRM,sig_alarm)<0){
		perror("signal error occured\n");
	}

	ai=host_serv(host);
	if (ai==NULL){
		printf("Unknown Host/Domain %s\n",host);
		exit(1);
	}
	h=gethost(ai->ai_addr,ai->ai_addrlen);
	printf("PING %s (%s) %d(%d) bytes of data\n",
				ai->ai_canonname?ai->ai_canonname:h,h,datalen,datalen+28);

	if(ai->ai_family==AF_INET){
		pr=&proto_v4;
	}else{
		printf("Unknown socket family %d\n",ai->ai_family);
		exit(1);
	}

	pr->sasend=ai->ai_addr;
	if( (pr->sarecv=calloc(1,ai->ai_addrlen))==NULL){
		printf("calloc error occured\n");
		exit(1);
	}
	pr->salen=ai->ai_addrlen;
	
	readloop();
	
	return 0;
}

struct addrinfo * host_serv(const char *host){
  int n;
  struct addrinfo hints;
  struct addrinfo *res;

  bzero(&hints,sizeof(struct addrinfo));
  hints.ai_flags=AI_CANONNAME;

  if( (n=getaddrinfo(host,NULL,&hints,&res))!=0){
    return NULL;
  }

  return res;
}

char * gethost(struct sockaddr *addr,size_t addr_len){
  struct sockaddr_in * addrin;
	int len;

  addrin=(struct sockaddr_in *)addr;
  inet_ntop(AF_INET,&addrin->sin_addr,ip,32);
	len=strlen(ip);
  ip[len]='\0';
  return ip;
}

