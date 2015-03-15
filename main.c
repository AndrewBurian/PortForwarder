/* ----------------------------------------------------------------------------
SOURCE FILE

Name:		main.c

Program:	Port Forwarder

Developer:	Andrew Burian
            Jordan Marling

Created On:	2015-03-08

Functions:
	int main(int argc, char** argv)

Description:
  The main portion of the port forwarding program

  * needs libconfread (github.com/andrewburian/configreader)

Revisions:
	(none)

---------------------------------------------------------------------------- */

#include "portforward.h"


// the array of targets
struct pf_target* targets = 0;
size_t targetCount = 0;

// known hosts
struct pf_host* hosts = 0;
size_t hostCount = 0;

//function prototypes
void forward();
struct pf_target *find_source_target(unsigned int host, unsigned int port);
struct pf_target *find_dest_target(unsigned int host, unsigned int port);
struct pf_host *find_host(unsigned int host, unsigned int port);
unsigned short csum(unsigned short *buf, int nwords);


/* ----------------------------------------------------------------------------
FUNCTION

Name:		Main

Prototype:	int main(int argc, char** argv)

Developer:	Andrew Burian

Created On:	2015-03-08

Parameters:
	Command line args

Return Values:
	0  success
  -1 error conditions

Description:
	Sets up the port forwarder. Reads the config file and sets up the targets list
  for forwarding.

Revisions:

  Jordan Marling
  2015-03-13
  Added the Listen function call

  Andrew Burian
  2015-03-15
  Added Checksum calculations for TCP at every sendto call

---------------------------------------------------------------------------- */
int main(int argc, char** argv){

  // the config file
  struct confread_file* confFile = 0;
  char* confFileName = 0;
  struct confread_section* sec = 0;

  // ports
  unsigned short int aPort = 0;
  unsigned short int bPort = 0;

  // counter
  size_t i = 0;
  size_t j = 0;

  // open the config
  confFileName = (argc > 1 ? argv[1] : DEFAULT_CONFIG);
  if(!(confFile = confread_open(confFileName))){
    fprintf(stderr, "Failed to open conf file: %s\n", confFileName);
    return -1;
  }

  // allocate as many targets as there are sections (-1 to skip root section)
  targets = (struct pf_target*)malloc(sizeof(struct pf_target) * confFile->count - 1);
  targetCount = confFile->count - 1;

  // setup the targets
  j = 1; // to skip root
  for(i = 0; i < targetCount; ++i, ++j){
    sec = confFile->sections[j];

    // check to see all sections are there
    if(!confread_find_value(sec, "port") || !confread_find_value(sec, "toport")
      || !confread_find_value(sec, "tohost")){

      // error
      fprintf(stderr, "Forward section %s malformed: missing field.\nIgnored.\n", sec->name);
      // shrink the number of targets needed
      targets = realloc(targets, sizeof(struct pf_target) * --targetCount);
      // don't advance i
      --i;
      continue;
    }

    // check to see we can scan the ports
    if(!sscanf(confread_find_value(sec, "port"), "%hu", &aPort) ||
      !sscanf(confread_find_value(sec, "toport"), "%hu", &bPort)){

      // error
      fprintf(stderr, "Forward section %s malformed: port NaN\nIgnored\n", sec->name);
      // shrink the number of targets needed
      targets = realloc(targets, sizeof(struct pf_target) * --targetCount);
      // don't advance i
      --i;
      continue;
    }

    // assign the host
    if((targets[i].host = inet_addr(confread_find_value(sec, "tohost"))) == INADDR_NONE){
      // error
      fprintf(stderr, "Forward section %s malformed: invalid host.\nIgnored.\n", sec->name);
      // shrink the number of targets needed
      targets = realloc(targets, sizeof(struct pf_target) * --targetCount);
      // don't advance i
      --i;
      continue;
    }

    // assign the ports
    targets[i].port.a_port = htons(aPort);
    targets[i].port.b_port = htons(bPort);
  }

  printf("Initialized %zu forwards\n", targetCount);

  // close the config
  confread_close(&confFile);

  forward();

  // cleanup
  free(targets);
  free(hosts);

  return 0;

}

/* ----------------------------------------------------------------------------
FUNCTION

Name:		Forward

Prototype:  void forward();

Developer:	Jordan Marling

Created On:	2015-03-13

Parameters:
	None

Return Values:
  None

Description:
	Listens for TCP packets coming in, then forwards them based on the data
  in the targets and hosts arrays.

Revisions:
  (none)

---------------------------------------------------------------------------- */
void forward() {

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
      printf("source target!\n");
      // set header information
      // ip_header->saddr = MY ADDRESS
      // ip_header->daddr = DST_ADDR
      tcp_header->source = target->port.a_port;

      // redo the checksum
      tcp_header->check = 0;
      tcp_header->check = csum((unsigned short*)tcp_header, ip_header->tot_len - (ip_header->ihl * 4));

      // forward
      sendto(socket_descriptor, buffer, datagram_length, 0, 0, 0);

      continue;
    }

    // if the packet is heading to a target
    target = find_dest_target(ip_header->daddr, tcp_header->dest);
    if (target != 0) {
      printf("dest target!\n");

      host = find_host(ip_header->saddr, tcp_header->source);
      if (host != 0) { // host is known and already added
        printf("host is known\n");
        // set header information
        tcp_header->dest = host->target->port.b_port;
        // ip_header->saddr = MY ADDRESS

        // redo the checksum
        tcp_header->check = 0;
        tcp_header->check = csum((unsigned short*)tcp_header, ip_header->tot_len - (ip_header->ihl * 4));

        //forward
        sendto(socket_descriptor, buffer, datagram_length, 0, 0, 0);

        // check to see if the packet was a reset packet
        if (tcp_header->rst == 1) {
          printf("reset\n");
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
        printf("Not in list.\n");
        // check if the packet is a SYN
        if (tcp_header->syn == 1) {
          printf("Add to list\n");
          // add host to list
          hostCount++;
          hosts = (struct pf_host*)realloc(hosts, sizeof(struct pf_host) * hostCount);

          hosts[hostCount - 1].host = ip_header->saddr;
          hosts[hostCount - 1].port = tcp_header->source;
          hosts[hostCount - 1].target = target;

          // set header information
          tcp_header->dest = target->port.b_port;
          ip_header->saddr = ip_header->daddr;
          ip_header->daddr = target->host;

          dst_addr.sin_family = AF_INET;
          dst_addr.sin_addr.s_addr = target->host;
          dst_addr.sin_port = target->port.b_port;


          // set the checksums
          ip_header->check = 0;
          tcp_header->check = 0;
          tcp_header->check = csum((unsigned short*)tcp_header, ip_header->tot_len - (ip_header->ihl * 4));

          printf("Sending to port %u\n", ntohs(tcp_header->dest));

          //forward
          sendto(socket_descriptor, (char*)ip_header, datagram_length, 0, (struct sockaddr*)&dst_addr, sizeof(struct sockaddr));
          printf("Send!\n");
          continue;
        }
      }
    }

  }
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

Name:		Checksum

Prototype:  unsigned short csum(unsigned short *buf, int nwords)

Developer:	Andrew Burian

Created On:	2015-03-15

Parameters:
  unsigned short *buf
    the start of the data to checksum
  int nwords
    the number of words to include in the sum

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
