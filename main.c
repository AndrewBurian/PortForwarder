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

  // the array of targets
  struct pf_target* targets = 0;
  size_t targetCount = 0;

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

  forward(targets, targetCount);

  // cleanup
  free(targets);

  return 0;

}
