#include <sr_protocol.h>
#include <sr_helpers.h>

void sr_handle_arp(struct sr_instance *sr,
                   uint8_t *packet, unsigned int len, struct sr_if *rec_iface)
{
    sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
    sr_arp_hdr_t *arp_hdr = packet_get_arp_hdr(packet);

    if (!arp_sanity_check(len))
    {
        Debug("Packet did not meet minimun length.\n");
        return;
    }

    switch (ntohs(arp_hdr->ar_op))
    {
    case arp_op_request:
        /* Handle arp request*/
        handle_arpreq(sr, eth_hdr, arp_hdr, rec_iface);
        break;
    case arp_op_reply:
        /* Handle arp reply*/
        handle_arprep(sr, arp_hdr, rec_iface);
        break;
    default:
        Debug("Wrong op code.\n");
        return;
    }
}

/* Handle arp request, if is request, construct reply and send it back */
void handle_arpreq(struct sr_instance *sr,
                   sr_ethernet_hdr_t *eth_hdr,
                   sr_arp_hdr_t *arp_hdr,
                   struct sr_if *sr_if)
{
    sr_arpcache_insert((&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    printf("Simple router sending arp request.\n");
    sr_send_arp_rep(sr, eth_hdr, arp_hdr, sr_if);
}

void sr_send_arp_rep(struct sr_instance *sr,
                     sr_ethernet_hdr_t *eth_hdr,
                     sr_arp_hdr_t *arp_hdr,
                     struct sr_if *sr_if)
{
    int packet_size = sizeof(eth_hdr) + size(arp_hdr);
    printf("Simple router sending arp reply.\n");
    uint8_t *packet = (uint8_t *)malloc(packet)size);
}

/* Handle arp reply, if is reply, save to cache and sendout request */
void handle_arprep(struct sr_instance *sr,
                   sr_arp_hdr_t *arp_hder,
                   struct sr_if *rec_iface)
{
    printf("Simple router sending arp request.\n")
}

void sr_send_arp_req(struct sr_instance *sr,
                     sr_arp_hdr_t *arp_hder,
                     struct sr_if *rec_iface)
{
}