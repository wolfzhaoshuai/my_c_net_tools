#include "ping.h"

void
sig_alarm(int signo)
{
  (*pr->fsend)();
   alarm(1);
   return;
}
