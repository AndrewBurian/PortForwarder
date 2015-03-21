#include "portforward.h"

// Globals

// the array of targets
struct pf_target* targets = 0;
size_t targetCount = 0;

// known hosts
struct pf_host* hosts = 0;
size_t hostCount = 0;

/* ----------------------------------------------------------------------------
FUNCTION

Name:		Forward

Prototype:  void forward(struct pf_target* targets, size_t targetCount);

Developer:	Jordan Marling

Created On:	2015-03-13

Parameters:
  struct pf_target* m_targets
    the array of targets
  size_t m_targetCount
    the number of targets in the array
  unsigned int ip
    the local ip address of the port forwarder machine

Return Values:
  None

Description:
  Listens for TCP packets coming in, then forwards them based on the data
  in the targets and hosts arrays.

Revisions:
  Andrew Burian
  2015-03-15
  Added args so that it could be moved out of main.c

---------------------------------------------------------------------------- */
void forward(struct pf_target* m_targets, size_t m_targetCount, unsigned int ip) {

  // socket descriptors
  int socket_descriptor;

  // ip variables
  char buffer[IP_DATA_LEN];
  int datagram_length;
  struct iphdr *ip_header;
  int hdrincl = 1;

  // transport layer
  struct tcphdr *tcp_header;
  struct sockaddr_in dst_addr = {0};

  // listening loop
  int running = 1;

  // forwarding
  struct pf_target *target;
  struct pf_host *host;

  // counter
  int i;

  // set globals
  targets = m_targets;
  targetCount = m_targetCount;

  // setup sockets
  if ((socket_descriptor = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
    perror("TCP Server Socket");
    return;
  }

  // tell the stack to let us handle the IP header
  if (setsockopt(socket_descriptor, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl)) == -1) {
      perror("SetSockOpt IP_HDRINCL");
  }

  while (running) {

    // read raw socket
    if ((datagram_length = recvfrom(socket_descriptor, buffer, IP_DATA_LEN, 0, 0, 0)) < 0) {
      perror("Reading Raw Socket");
      running = 0;
      return;
    }

    // get the header addresses
    ip_header = (struct iphdr*)buffer;
    tcp_header = (struct tcphdr*)(buffer + (ip_header->ihl * 4));

    //check if the datagram is TCP.
    if (ip_header->protocol != IPPROTO_TCP) {
      continue;
    }

    // if the packet is coming from a target
    target = find_source_target(ip_header->saddr, tcp_header->source);
    if (target != 0) {

      host = find_host_by_target(ip_header->saddr, tcp_header->dest);
      if (host == 0) {
        printf("Could not find host.\n");
        continue;
      }

      // destination address
      dst_addr.sin_family = AF_INET;
      dst_addr.sin_addr.s_addr = host->host;
      dst_addr.sin_port = target->port.a_port;

      // set the source ip to be this forwarder
      ip_header->saddr = ip;

      // set the target to be the original host
      ip_header->daddr = host->host;

      // set the source port to be the forwarded port
      tcp_header->source = target->port.a_port;

      // redo the checksum
      tcp_header->check = 0;
      tcp_header->check = tcp_csum(ip_header, tcp_header);

      // forward
      if (sendto(socket_descriptor, buffer, datagram_length, 0, (struct sockaddr*)&dst_addr, sizeof(struct sockaddr)) == -1) {
        printf("error sending...\n");
      }

      continue;
    }

    // if the packet is heading to a target
    target = find_dest_target(ip_header->daddr, tcp_header->dest);
    if (target != 0) {

      host = find_host(ip_header->saddr, tcp_header->source);
      if (host != 0) { // host is known and already added


        // set header information
        tcp_header->dest = host->target->port.b_port;
        ip_header->saddr = ip;
        ip_header->daddr = target->host;

        dst_addr.sin_family = AF_INET;
        dst_addr.sin_addr.s_addr = target->host;
        dst_addr.sin_port = host->target->port.b_port;

        // set the checksums
        ip_header->check = 0;
        tcp_header->check = 0;
        tcp_header->check = tcp_csum(ip_header, tcp_header);

        //forward
        sendto(socket_descriptor, (char*)ip_header, datagram_length, 0, (struct sockaddr*)&dst_addr, sizeof(struct sockaddr));


        // check to see if the packet was a reset packet
        if (tcp_header->rst == 1 || tcp_header->fin == 1) {
          printf("fin\n");
          // remove from hosts list

          // find the index of the host
          for(i = 0; i < hostCount; i++) {
            if (hosts[i].host == host->host && hosts[i].port == tcp_header->source) {
              break;
            }
          }

          // swap the last host with it
          memcpy(&hosts[i], &hosts[hostCount - 1], sizeof(struct pf_host));

          // remove the last host in the list
          hostCount--;
          hosts = (struct pf_host*)realloc(hosts, sizeof(struct pf_host) * hostCount);

        }

        continue;
      }
      else { // we do not have this host stored.
        // check if the packet is a SYN
        if (tcp_header->syn == 1) {
          // add host to list
          hostCount++;
          hosts = (struct pf_host*)realloc(hosts, sizeof(struct pf_host) * hostCount);

          hosts[hostCount - 1].host = ip_header->saddr;
          hosts[hostCount - 1].port = tcp_header->source;
          hosts[hostCount - 1].target = target;

          // set header information
          tcp_header->dest = target->port.b_port;
          ip_header->saddr = ip;
          ip_header->daddr = target->host;

          dst_addr.sin_family = AF_INET;
          dst_addr.sin_addr.s_addr = target->host;
          dst_addr.sin_port = target->port.b_port;

          // set the checksums
          ip_header->check = 0;
          tcp_header->check = 0;
          tcp_header->check = tcp_csum(ip_header, tcp_header);

          //forward
          sendto(socket_descriptor, (char*)ip_header, datagram_length, 0, (struct sockaddr*)&dst_addr, sizeof(struct sockaddr));
          continue;
        }
      }
    }

  }

  free(hosts);
}

/* ----------------------------------------------------------------------------
FUNCTION

Name:		Find Source Target

Prototype:  struct pf_target *find_source_target(unsigned int host, unsigned int port)

Developer:	Jordan Marling

Created On:	2015-03-13

Parameters:
  host: The host to find
  port: The port to find

Return Values:
  A pointer to the forwarding target or a null pointer if one wasn't found.

Description:
  This function finds the target for the source port and hostname.

Revisions:
  (none)

---------------------------------------------------------------------------- */
struct pf_target *find_source_target(unsigned int host, unsigned int port) {

  int i;

  //return if we find a target match
  for (i = 0; i < targetCount; i++) {
    if (targets[i].host == host && targets[i].port.b_port == port) {
      return &targets[i];
    }
  }

  // return a null pointer if a target isn't found
  return 0;
}

/* ----------------------------------------------------------------------------
FUNCTION

Name:		Find Destionation Target

Prototype:  struct pf_target *find_dest_target(unsigned int host, unsigned int port)

Developer:	Jordan Marling

Created On:	2015-03-13

Parameters:
  host: The host to find
  port: The port to find

Return Values:
  A pointer to the forwarding target or a null pointer if one wasn't found.

Description:
  This function finds the target for the destination port and hostname.

Revisions:
  (none)

---------------------------------------------------------------------------- */
struct pf_target *find_dest_target(unsigned int host, unsigned int port) {

  int i;

  //return if we find a target match
  for (i = 0; i < targetCount; i++) {
    // if (targets[i].host == host && targets[i].port.a_port == port) {
    //   return &targets[i];
    // }
    if (targets[i].port.a_port == port) {
      return &targets[i];
    }
  }

  // return a null pointer if a target isn't found
  return 0;
}

/* ----------------------------------------------------------------------------
FUNCTION

Name:		Find Host

Prototype:  struct pf_target *find_host(unsigned int host, unsigned int port)

Developer:	Jordan Marling

Created On:	2015-03-13

Parameters:
  host: The host to find
  port: The port to find

Return Values:
  A pointer to the forwarded host or a null pointer if one wasn't found.

Description:
  This function finds the forwarding client from the host and port.

Revisions:
  (none)

---------------------------------------------------------------------------- */
struct pf_host *find_host(unsigned int host, unsigned int port) {

  int i;

  //return if we find a host match
  for (i = 0; i < hostCount; i++) {
    if (hosts[i].host == host && hosts[i].port == port) {
      return &hosts[i];
    }
  }

  // return a null pointer if a host isn't found
  return 0;
}

/* ----------------------------------------------------------------------------
FUNCTION

Name:		Find Host By Target

Prototype:  struct pf_target *find_host_by_target(unsigned int target_host, unsigned int port)

Developer:	Jordan Marling

Created On:	2015-03-13

Parameters:
  target_host: The target to find
  port: The port to find

Return Values:
  A pointer to the forwarded host or a null pointer if one wasn't found.

Description:
  This function finds the forwarding client from the target host and port.

Revisions:
  (none)

---------------------------------------------------------------------------- */
struct pf_host *find_host_by_target(unsigned int target_host, unsigned int port) {
  int i;

  //return if we find a host match
  for (i = 0; i < hostCount; i++) {
    if (hosts[i].target->host == target_host && hosts[i].port == port) {
      return &hosts[i];
    }
  }

  // return a null pointer if a host isn't found
  return 0;
}
