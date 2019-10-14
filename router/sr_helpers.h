#ifndef SR_HELPERS_H
#define SR_HELPERS_H

#include "sr_protocol.h"

sr_ethernet_hdr_t *get_eth_hdr(uint8_t *packet);
sr_icmp_hdr_t *get_icmp_hdr(uint8_t *packet);
sr_arp_hdr_t *get_arp_hdr(uint8_t *packet);
sr_ip_hdr_t *get_ip_hdr(uint8_t *packet);

#endif