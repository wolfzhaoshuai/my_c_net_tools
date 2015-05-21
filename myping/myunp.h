#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>

#define LISTENQ 1024
#define MAXLINE 65508
#define SERV_PORT 9976
#define INET_ADDRSTRLEN 16
