#ifndef SR_HELPERS_H
#define SR_HELPERS_H

sr_arp_hdr_t *get_arp_hdr(uint8_t *packet);
sr_ethernet_hdr_t *get_ethernet_hdr(uint8_t *buf);
sr_ip_hdr_t *get_ip_hdr(uint8_t *buf);
sr_icmp_hdr_t *get_icmp_hdr(uint8_t *buf);
sr_icmp_t3_hdr_t *get_icmp_t3_hdr(uint8_t *buf);
uint8_t arp_sanity_check(unsigned int frame_len);
uint8_t ip_sanity_check(sr_ip_hdr_t *ip_hdr, unsigned int len);
uint8_t icmp_sanity_check(sr_ip_hdr_t *ip_hdr, sr_icmp_hdr_t *icmp_hdr, unsigned int len);
void add_ethernet_header(sr_ethernet_hdr_t *eth_hdr, uint8_t *tha, uint8_t *sha, unsigned int packet_type);
void add_ip_header(sr_ip_hdr_t *ip_hdr,
                   unsigned int len,
                   unsigned int ip_hl,
                   unsigned int ip_v,
                   uint8_t ip_tos,
                   uint8_t ip_p,
                   uint32_t ip_src,
                   uint32_t ip_dst);
void add_icmp_t3_header(sr_icmp_t3_hdr_t *icmp_t3_hdr, uint8_t type, uint8_t code, uint8_t *data);
void add_icmp_header(sr_icmp_hdr_t *icmp_hdr, uint8_t type, uint8_t code);
#endif