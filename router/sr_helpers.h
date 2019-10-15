#ifndef SR_HELPERS_H
#define SR_HELPERS_H

sr_arp_hdr_t *get_arp_hdr(uint8_t *packet);
sr_ethernet_hdr_t *get_ethernet_hdr(uint8_t *buf);
sr_ip_hdr_t *get_ip_hdr(uint8_t *buf);
sr_icmp_hdr_t *get_icmp_hdr(uint8_t *buf);
sr_icmp_t3_hdr_t *get_icmp_t3_hdr(uint8_t *buf);
uint8_t arp_sanity_check(unsigned int frame_len);
uint8_t ip_sanity_check(sr_ip_hdr_t *ip_hdr, unsigned int len);

#endif