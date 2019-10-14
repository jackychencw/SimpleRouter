#ifndef SR_HELPERS_H
#define SR_HELPERS_H

sr_arp_hdr_t *get_arp_hdr(uint8_t *packet);
sr_ethernet_hdr_t *get_ethernet_hdr(uint8_t *buf);
uint8_t arp_sanity_check(unsigned int frame_len);

#endif