#include "ping.h"
void
tv_sub(struct timeval *out,struct timeval *in)
{
  if(out->tv_usec < in->tv_usec){
		out->tv_sec-=1;
		out->tv_usec = out->tv_usec + 1000000 - in->tv_usec;
	}else{
		out->tv_usec -= in->tv_usec;
	}	
  out->tv_sec -= in->tv_sec;
}
