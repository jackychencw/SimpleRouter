#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_helpers.h"
#include "sr_utils.h"
#include "sr_router.h"

sr_arp_hdr_t *get_arp_hdr(uint8_t *buf)
{
    return (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
}

sr_ethernet_hdr_t *get_ethernet_hdr(uint8_t *buf)
{
    return (sr_ethernet_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
};

sr_ip_hdr_t *get_ip_hdr(uint8_t *buf)
{
    return (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
}

sr_icmp_hdr_t *get_icmp_hdr(uint8_t *buf)
{
    return (sr_icmp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
}

sr_icmp_t3_hdr_t *get_icmp_t3_hdr(uint8_t *buf)
{
    return (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
}

uint8_t arp_sanity_check(unsigned int len)
{
    int min_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    return len >= min_len;
}

uint8_t ip_sanity_check(sr_ip_hdr_t *ip_hdr, unsigned int len)
{
    int min_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    uint16_t tmp_sum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint8_t passed = (tmp_sum == cksum(ip_hdr, sizeof(sr_ip_hdr_t))) && (len >= min_len);
    ip_hdr->ip_sum = tmp_sum;
    return passed;
}

void add_ethernet_header(sr_ethernet_hdr_t *eth_hdr, uint8_t *tha, uint8_t *sha, uint16_t packet_type)
{
    memcpy(eth_hdr->ether_dhost, tha, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, sha, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(packet_type);
}

void add_ip_header(sr_ip_hdr_t *ip_hdr,
                   unsigned int len,
                   unsigned int ip_hl,
                   unsigned int ip_v,
                   uint8_t ip_tos,
                   uint8_t ip_p)
{
    ip_hdr->ip_hl = ip_hl;
    ip_hdr->ip_v = ip_v;
    ip_hdr->ip_tos = ip_tos;
    ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = INIT_TTL;
    ip_hdr->ip_p = ip_p;
    ip_hdr->ip_sum = 0;
}

void add_icmp_msg(sr_icmp_hdr_t *icmp_hdr, uint8_t type, uint8_t code)
{
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;
}
