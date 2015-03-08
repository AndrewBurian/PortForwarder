#ifndef PORTFORWARD_H
#define PORTFORWARD_H

#define DEFAULT_CONFIG "forwards.conf"

#include <sys/socket.h>
#include <arpa/inet.h>

struct pf_port{
  unsigned short int a_port;
  unsigned short int b_port;
};

struct pf_target{
  unsigned int host;
  struct pf_port port;
};

struct pf_host{
  unsigned int host;
  unsigned short int port;
  struct pf_target* target;
};

int* forwardedPorts = 0;


#endif
