#include "myunp.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define BUFSIZE 1500

/*global variables*/
char sendbuf[BUFSIZE];
int datalen; //bytes of data following ICMP header,including timestamp
char *host;
int nsent; //sequence counter add 1 per send
pid_t pid; //PID identifier
int sockfd;

/*function prototype*/
void proc_v4(char *,ssize_t,struct msghdr *,struct timeval *);
void send_v4(void);
void readloop(void);
void sig_alarm(int);
void tv_sub(struct timeval *,struct timeval *);

struct proto{
  void (*fproc)(char *,ssize_t,struct msghdr *,struct timeval *);
  void(*fsend)(void);
  void(*finit)(void);
  struct sockaddr *sasend; //sockaddr() for send,from getaddrinfo
  struct sockaddr *sarecv;//sockaddr() for receiving
  socklen_t salen;//length of sockaddr()
  int icmpproto;//IPPROTO_xxx vlaue for ICMP
}*pr;

