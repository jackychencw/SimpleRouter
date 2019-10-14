#include "sr_protocol.h"

sr_arp_hdr_t *get_arp_hdr(uint8_t *buf)
{
    return (sr_arp_hdr_t *)(buf + sizeof(sr_arp_hdr_t));
}

sr_ethernet_hdr_t *get_ethernet_hdr(uint8_t *buf)
{
    return (sr_eth_hdr_t *)(buf + sizeof(st_ethernet_hdr_t));
};

bool arp_sanity_check(unsigned int len)
{
    int minlength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    return len >= minlength;
}
