
#include "portforward.h"

#define FIREWALL_RULE "iptables -%c OUTPUT -p tcp %s %d --tcp-flags RST RST -j DROP > /dev/null 2>&1"
#define FIREWALL_RULE_MAX_LEN 97

void firewall_invoke_srcport(int port) {

  char rule[FIREWALL_RULE_MAX_LEN];

  // delete rule
  sprintf(rule, FIREWALL_RULE, 'D', "--sport", port);
  system(rule);

  // add rule
  sprintf(rule, FIREWALL_RULE, 'A', "--sport", port);
  system(rule);
}

void firewall_invoke_dstport(int port) {

  char rule[FIREWALL_RULE_MAX_LEN];

  // delete rule
  sprintf(rule, FIREWALL_RULE, 'D', "--dport", port);
  system(rule);

  // add rule
  sprintf(rule, FIREWALL_RULE, 'A', "--dport", port);
  system(rule);

}
