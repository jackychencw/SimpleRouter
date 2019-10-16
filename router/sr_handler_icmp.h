#ifndef SR_HANDLER_ICMP_H
#define SR_HANDLER_ICMP_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

int sr_handle_icmp_t3(struct sr_instance *sr,
                      uint8_t *buf,
                      uint8_t icmp_type,
                      uint8_t icmp_code,
                      struct sr_if *rec_iface);
uint8_t *create_icmp_packet(uint8_t tha, uint8_t sha, struct sr_ip_hdr *dest_ip_hdr, uint8_t icmp_type, uint8_t icmp_code);
void handle_icmp_unreachable(struct sr_instance *sr);
void handle_icmp_echo_reply(struct sr_instance *sr);
void sr_handle_icmp(
    struct sr_instance *sr,
    uint8_t *packet,
    unsigned int len,
    struct sr_if *iface,
    uint8_t type,
    uint8_t code);

#endif
