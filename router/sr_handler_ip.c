#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_helpers.h"
#include "sr_utils.h"
#include "sr_handler_icmp.h"
#include "sr_handler_arp.h"

void sr_ip_packet_forward(struct sr_instance *sr,
                          uint8_t *packet,
                          unsigned int len,
                          struct sr_if *src_iface,
                          struct sr_if *tar_iface)
{
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
    if (!entry) /* if it's not cached */
    {
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, tar_iface->name);
        sr_send_5_arp_req(sr, req);
    }
    else /* if it's cached */
    {
        memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, tar_iface->addr, ETHER_ADDR_LEN);
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        sr_send_packet(sr, packet, len, tar_iface->name);
        free(entry);
    }
}

void handle_icmp_proto(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *iface)
{
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    if (!icmp_sanity_check(ip_hdr, icmp_hdr, len))
    {
        printf("ICMP sanity check failed, drop\n");
        return;
    }
    sr_handle_icmp_reply(sr, packet, len, icmp_hdr->icmp_type, icmp_hdr->icmp_code, iface);
}

void sr_handle_ip(struct sr_instance *sr,
                  uint8_t *packet,
                  unsigned int len,
                  struct sr_if *iface)
{
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint32_t ip_dst = ip_hdr->ip_dst;

    if (!ip_sanity_check(ip_hdr, len))
    {
        printf("ERROR: ip packet didn't pass sanity check...\n");
        return;
    }

    ip_hdr->ip_ttl--;

    if (ip_hdr->ip_ttl <= 0)
    {
        printf("ERROR: ip packet ttl expired... \n");
        sr_handle_icmp_t3(sr, packet, icmp_time_exceed_type, 0, iface);
        return;
    }
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /*1. if it's for me */
    if (ip_dst == iface->ip)
    {
        uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
        switch (ip_proto)
        {
        case (ip_protocol_icmp): /*2. if it's ICMP echo req, send echo reply */
            handle_icmp_proto(sr, packet, len, iface);
            break;
        case (ip_protocol_tcp | ip_protocol_udp): /*3. if it's tcp/udp, send ICMP port unreachable */
            sr_handle_icmp_t3(sr, packet, icmp_dest_unreachable_type, icmp_port_unreachable_code, iface);
            break;
        default:
            printf("No valid ip protocol found.\n");
            return;
        }
    }
    else /*4. if it's not for me */
    {
        struct in_addr ip_addr;
        ip_addr.s_addr = ip_dst;

        /*5. check routing table, perform lightweight packet marking */
        struct sr_rt *rt = sr_rt_lpm_lookup(sr, ip_addr);

        /*6. if there is a match */
        if (rt)
        {
            struct sr_if *target_iface = sr_get_interface(sr, rt->interface);
            if (target_iface)
            {
                printf("found interface, forward it\n");
                sr_ip_packet_forward(sr, packet, len, iface, target_iface);
                return;
            }
            else
            {
                sr_handle_icmp_t3(sr, packet, icmp_dest_unreachable_type, icmp_net_unreachable_code, iface);
                return;
            }
        }
        /*8. if there isn't a match */
        else
        {
            /*9. send ICMP net unreachable*/
            sr_handle_icmp_t3(sr, packet, icmp_dest_unreachable_type, icmp_net_unreachable_code, iface);
            return;
        }
    }
    return;
}