/* ----------------------------------------------------------------------------
SOURCE FILE

Name:		firewall_rules.c

Program:	Port Forwarder

Developer:	Jordan Marling

Created On:	2015-03-21

Functions:
  void firewall_invoke_srcport(int port)
  void firewall_invoke_dstport(int port)

Description:
  Contains functions to invoke firewall rules needed by application.

Revisions:
	(none)

---------------------------------------------------------------------------- */


#include "portforward.h"


#define FIREWALL_RULE "iptables -%c OUTPUT -p tcp %s %d --tcp-flags RST RST -j DROP > /dev/null 2>&1"
#define FIREWALL_RULE_MAX_LEN 97


/* ----------------------------------------------------------------------------
FUNCTION

Name:		Invoke Firewall Source Port

Prototype:  void firewall_invoke_srcport(int port)

Developer:	Jordan Marling

Created On:	2015-03-21

Parameters:
  int port
    The source port to not allow resets from

Return Values:
  void

Description:
  Invokes a firewall rule to not allow TCP RST packets outgoing on the source
  port.

Revisions:
  (none)

---------------------------------------------------------------------------- */
void firewall_invoke_srcport(int port) {

  char rule[FIREWALL_RULE_MAX_LEN];

  // delete rule
  sprintf(rule, FIREWALL_RULE, 'D', "--sport", port);
  system(rule);

  // add rule
  sprintf(rule, FIREWALL_RULE, 'A', "--sport", port);
  system(rule);
}

/* ----------------------------------------------------------------------------
FUNCTION

Name:		Invoke Firewall Destination Port

Prototype:  void firewall_invoke_dstport(int port)

Developer:	Jordan Marling

Created On:	2015-03-21

Parameters:
  int port
    The destination port to not allow resets from

Return Values:
  void

Description:
  Invokes a firewall rule to not allow TCP RST packets outgoing on the destination
  port.

Revisions:
  (none)

---------------------------------------------------------------------------- */
void firewall_invoke_dstport(int port) {

  char rule[FIREWALL_RULE_MAX_LEN];

  // delete rule
  sprintf(rule, FIREWALL_RULE, 'D', "--dport", port);
  system(rule);

  // add rule
  sprintf(rule, FIREWALL_RULE, 'A', "--dport", port);
  system(rule);

}
