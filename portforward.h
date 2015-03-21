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

// for TCP checksumming
struct pseudoTcpHeader {
  unsigned int ip_src;
  unsigned int ip_dst;
  unsigned char zero;
  unsigned char protocol;
  unsigned short tcp_len;
  // struct tcphdr tcph;
};

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

//function prototypes
void forward(struct pf_target* m_targets, size_t m_targetCount, unsigned int ip);
struct pf_target *find_source_target(unsigned int host, unsigned int port);
struct pf_target *find_dest_target(unsigned int host, unsigned int port);
struct pf_host *find_host_by_target(unsigned int target_host, unsigned int port);
struct pf_host *find_host(unsigned int host, unsigned int port);
unsigned short csum(unsigned short *buf, int nwords);
unsigned short tcp_csum(struct iphdr *ip_header, struct tcphdr *tcp_header);

#endif
