#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_helpers.h"

sr_arp_hdr_t *get_arp_hdr(uint8_t *buf)
{
    return (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
}

sr_ethernet_hdr_t *get_ethernet_hdr(uint8_t *buf)
{
    return (sr_ethernet_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
};

sr_ip_hdr_t *get_IP_hdr(uint8_t *buf)
{
    /*TODO*/
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

uint8_t ip_sanity_check(unsigned int len)
{
}