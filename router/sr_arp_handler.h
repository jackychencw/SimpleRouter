#include <sr_protocol.h>
#ifndef SR_ARP_HANDLER_H
#define SR_ARP_HANDLER_H

void sr_arp_handler(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *rec_iface);

void sr_handle_arpreq(struct sr_instance *sr, sr_ethernet_hdr_t *req_eth_hdr, sr_arp_hdr_t *req_arp_hdr, struct sr_if *rec_iface);

void sr_handle_arprep(struct sr_instance *sr, sr_arp_hdr_t *arp_hdr, struct sr_if *rec_iface);

#endif