/* ----------------------------------------------------------------------------
HEADER FILE

Name:		portforward.h

Program:	Port Forwarder

Developer:	Andrew Burian

Created On:	2015-03-08

Description:
	All the structs and functions needed for the port forwarding program

  * needs libconfread (github.com/andrewburian/configreader)

Revisions:
	(none)

---------------------------------------------------------------------------- */

#ifndef PORTFORWARD_H
#define PORTFORWARD_H

#define DEFAULT_CONFIG  "forwards.conf"
#define IP_DATA_LEN     65536

#include <sys/socket.h>
#include <arpa/inet.h>
#include <confread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

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

#endif
