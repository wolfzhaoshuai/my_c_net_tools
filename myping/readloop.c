#include "ping.h"

void readloop(void)
{
  int size;
  char recvbuf[BUFSIZE];
  char controlbuf[BUFSIZE];
  struct msghdr msg;
  struct iovec iov;
  ssize_t n;
  struct timeval tval;

  if( (sockfd=socket(pr->sasend->sa_family,SOCK_RAW,pr->icmpproto))<0){
    perror("Readloop socket creation failed,most probably permittion denied\n");
		exit(1);
  }

  setuid(getuid());//become the leader of the process group,don't need special permission any more,executed in root
  if(pr->finit)
    (*pr->finit)();
  
  size=60*1024;
  setsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));
  
  sig_alarm(SIGALRM);//send first packet

  iov.iov_base=recvbuf;
  iov.iov_len=sizeof(recvbuf);
  msg.msg_name=pr->sarecv;
  msg.msg_iov=&iov;
  msg.msg_iovlen=1;
  msg.msg_control=controlbuf;
  while(1){
    msg.msg_namelen=pr->salen;
    msg.msg_controllen=sizeof(controlbuf);
    n=recvmsg(sockfd,&msg,0);
    if(n<0){
			perror("recvmsg error");
			break;
    }
    
    if(gettimeofday(&tval,NULL) !=0){
      perror("gettimeofday in readloop() faliure");
			break;
    }
    (*pr->fproc)(recvbuf,n,&msg,&tval);
  }
}
