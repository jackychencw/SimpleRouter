#ifndef SR_ARP_HANDLER_H
#define SR_ARP_HANDLER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request);
struct sr_if *sr_rt_lookup(struct sr_instance *sr, uint32_t dest);
int sr_send_arprep(struct sr_instance *sr,
                   sr_ethernet_hdr_t *origin_ethernet_hder,
                   sr_arp_hdr_t *origin_arp_hder,
                   struct sr_if *received_interface);
int sr_send_arpreq(struct sr_instance *sr, uint32_t destination);
void sr_handle_arp(struct sr_instance *sr,
                   uint8_t *packet,
                   unsigned int len,
                   struct sr_if *sr_interface);

#endif