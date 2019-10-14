#include <sr_protocol.h>

void sr_handle_arp(struct sr_instance *sr,
                   uint8_t *packet, unsigned int len, struct sr_if *rec_iface)
{
    sr_ethernet_hdr_t *eth_hdr = packet_get_eth_hdr(packet);
    sr_arp_hdr_t *arp_hdr = packet_get_arp_hdr(packet);

    if (!sanity_check_arp_packet_len_ok(len))
    {
        Debug("Sanity check for ARP packet length failed! Ignoring ARP.\n");
        return;
    }

    Debug("Sensed an ARP frame, processing it\n");

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
        Debug("Didn't get an ARP frame I understood, quitting!\n");
        return;
    }
}

void handle_arpreq(struct sr_instance *sr,
                   sr_ethernet_hdr_t *eth_hdr,
                   sr_arp_hdr_t *arp_hder,
                   struct sr_if *sr_if)
{
    sr_arpcache_insert((&sr->cache, arp_hder->ar_sha, arp_hder->ar_sip);
    sr_send_arp_rep(sr, req_eth_hdr, req_arp_hdr, sr_if);
}

void handle_arprep(struct sr_instance *sr,
                   sr_arp_hdr_t *arp_hder,
                   struct sr_if *rec_iface)
{
}