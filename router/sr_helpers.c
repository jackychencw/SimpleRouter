#include "sr_protocol.h"

sr_arp_hdr_t *get_arp_hdr(uint8_t *buf)
{
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
    return arp_hdr;
}
