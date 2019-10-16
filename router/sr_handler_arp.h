#ifndef SR_HANDLER_ARP_H
#define SR_HANDLER_ARP_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request);
struct sr_if *sr_rt_lookup(struct sr_instance *sr, uint32_t dest);
int send_arp_packet(struct sr_instance *sr, uint8_t *sha, uint32_t sip, uint8_t *tha, uint32_t tip, unsigned short opcode, struct sr_if *interface);
void sr_handle_arp_op_req(struct sr_instance *sr, sr_ethernet_hdr_t *eth_hder, sr_arp_hdr_t *arp_hder, struct sr_if *interface);
int sr_handle_arp_op_rep(struct sr_instance *sr, uint32_t destination);
void sr_handle_arp(struct sr_instance *sr,
                   uint8_t *packet,
                   unsigned int len,
                   struct sr_if *sr_interface);

#endif