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

void sr_handle_ip(struct sr_instance *sr,
                  uint8_t *packet,
                  unsigned int len,
                  struct sr_if *iface)
{
    sr_ethernet_hdr_t *eth_hdr = get_ethernet_hdr(packet);
    sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
    uint32_t ip_dst = ip_hdr->ip_dst;

    if (!ip_sanity_check(ip_hdr, len))
    {
        printf("ERROR: ip packet didn't pass sanity check...");
        return;
    }

    ip_hdr->ip_ttl -= 1;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /*1. if it's for me */
    if (ip_dst == iface->ip)
    {
        printf("This is an request for me, handling ... \n");
        uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
        switch (ip_proto)
        {
        case (ip_protocol_icmp): /*2. if it's ICMP echo req, send echo reply */
            printf("Hello icmp\n");
            sr_handle_icmp(sr, packet, len, iface, icmp_echo_reply_type, 0);
            break;
        case (ip_protocol_tcp | ip_protocol_udp): /*3. if it's tcp/udp, send ICMP port unreachable */
            printf("hello udp/tcp\n");
            sr_handle_icmp(sr, packet, len, iface, icmp_dest_unreachable_type, icmp_port_unreachable_code);
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
            /*7. check if there is a arp cache exists */
            struct sr_if *target_iface = sr_get_interface(sr, rt->interface);
            if (target_iface)
            {
                printf("There is a match, about to check arp cache\n");
            }
        }
        /*8. if there isn't a match */
        else
        {
            /*9. send ICMP net unreachable*/
            printf("There is no match, should send icmp net unreachable\n");
        }
    }

    /*10. if no arp cache */
    /*11. send arp request and resent >5 times */
    /*12. if exists arp cache */
    /*13. send frame to next hope */
}