#include "portforward.h"

/* ----------------------------------------------------------------------------
FUNCTION

Name:		TCP Checksum

Prototype:  unsigned short tcp_csum(unsigned short *packet)

Developer:	Andrew Burian

Created On:	2015-03-15

Parameters:
  unsigned short *packet
    the start of the tcp packet to checksum

Return Values:
  The checksum of the data block

Description:
  Does a checksum on the TCP "pseudo header" because they couldn't just use
  a standard checksum could they?

Revisions:
  2015-03-20
  Jordan Marling
  Fixed the algorithm. The TCP header wasn't being copied fully because it
  was in network byte order. also it now takes into account tcp header options.

---------------------------------------------------------------------------- */
unsigned short tcp_csum(struct iphdr *ip_header, struct tcphdr *tcp_header){

  unsigned short total_len = ntohs(ip_header->tot_len);
  unsigned short checksum;

  // tcp lengths
  int tcpopt_len = (tcp_header->doff * 4) - 20;
  int tcpdatalen = total_len - (tcp_header->doff*4) - (ip_header->ihl*4);

  // pseudo header
  struct pseudoTcpHeader pseudohead;
  int totaltcp_len = sizeof(struct pseudoTcpHeader) + sizeof(struct tcphdr) + tcpopt_len + tcpdatalen;
  unsigned short *psuedoheader_tcpsegment = (unsigned short*)malloc(totaltcp_len);


  pseudohead.ip_src = ip_header->saddr;
  pseudohead.ip_dst = ip_header->daddr;
  pseudohead.zero = 0;
  pseudohead.protocol = IPPROTO_TCP;
  pseudohead.tcp_len = htons(sizeof(struct tcphdr) + tcpopt_len + tcpdatalen);


  // put the pseudo header into memory
  memcpy((unsigned char*)psuedoheader_tcpsegment, &pseudohead, sizeof(struct pseudoTcpHeader));
  // put the tcp header into memory
  memcpy((unsigned char*)psuedoheader_tcpsegment + sizeof(struct pseudoTcpHeader), (unsigned char*)tcp_header, sizeof(struct tcphdr));
  // put the tcp options into memory
  memcpy((unsigned char*)psuedoheader_tcpsegment + sizeof(struct pseudoTcpHeader) + sizeof(struct tcphdr), (unsigned char*)ip_header + (ip_header->ihl * 4) + sizeof(struct tcphdr), tcpopt_len);
  // put the tcp data into memory
  memcpy((unsigned char*)psuedoheader_tcpsegment + sizeof(struct pseudoTcpHeader) + sizeof(struct tcphdr) + tcpopt_len, (unsigned char*)tcp_header + (tcp_header->doff * 4), tcpdatalen);

  checksum = csum(psuedoheader_tcpsegment, totaltcp_len);

  free(psuedoheader_tcpsegment);

  return checksum;
}

/* ----------------------------------------------------------------------------
FUNCTION

Name:		Checksum

Prototype:  unsigned short csum(unsigned short *buf, int nwords)

Developer:	Andrew Burian

Created On:	2015-03-15

Parameters:
  unsigned short *buf
    the start of the data to checksum
  int nwords
    the number of short (16b) words to include in the sum

Return Values:
  The checksum of the data block

Description:
   Taken from an implementation of RFC 1071, computes a standard internet
   checksum

Revisions:
  2015-03-20
  Jordan Marling
  Changed from words to bytes

---------------------------------------------------------------------------- */
unsigned short csum(unsigned short *buf, int nwords){

  unsigned long sum;


  for(sum = 0; nwords > 1; nwords -= 2)  {
    sum += *buf++;
  }

  // add the left-over byte
  if(nwords > 0)
    sum += *(unsigned char *)buf;

  // turn the 32 bit words to 16 bit.
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return (unsigned short)~sum;
}
