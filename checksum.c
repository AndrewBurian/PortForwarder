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
  (none)

---------------------------------------------------------------------------- */
unsigned short tcp_csum(unsigned short *packet){

  // the headers needed
  struct iphdr *ip_header = (struct iphdr*)packet;

  // the pseudo header to assemble
  struct pseudoTcpHeader hdr = {0};

  // amass the pseudo header
  hdr.ip_src = ip_header->saddr;
  hdr.ip_dst = ip_header->daddr;
  hdr.protocol = ip_header->protocol;
  hdr.tcp_len = ip_header->tot_len - (ip_header->ihl * 4);
  hdr.tcph = *(struct tcphdr*)(ip_header + ip_header->tot_len - (ip_header->ihl * 4));

  // checksum it
  return csum((unsigned short*)&hdr, sizeof(hdr) / 2);

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
  (none)

---------------------------------------------------------------------------- */
unsigned short csum(unsigned short *buf, int nwords){

  unsigned long sum;

  for(sum=0; nwords>0; nwords--){
    sum += *buf++;
  }

  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);

  return (unsigned short)(~sum);
}
