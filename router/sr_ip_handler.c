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

struct sr_if *sr_rt_lookup(struct sr_instance *sr, uint32_t dest)
{
    struct sr_rt *rt = sr->routing_table;
    while (rt)
    {
        struct sr_rt *next = rt->next;
        if (dest == rt->dest.s_addr)
        {
            return sr_get_interface(sr, rt->interface);
        }
        else
        {
            rt = next;
        }
    }
    /* No interface found. */
    return NULL;
}

void sr_handle_ip(struct sr_instance *sr,
                  uint8_t *packet,
                  unsigned int len,
                  struct sr_if *iface)
{
    sr_ethernet_hdr_t *eth_hdr = get_ethernet_hdr(packet);
    sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
    uint32_t ip_dst = ip_hdr->ip_dst;
    printf("Handling ip packet !!\n\n");
    fprintf(stderr, "\tversion: %d\n", ip_hdr->ip_v);
    fprintf(stderr, "\theader length: %d\n", ip_hdr->ip_hl);
    fprintf(stderr, "\ttype of service: %d\n", ip_hdr->ip_tos);
    fprintf(stderr, "\tlength: %d\n", ntohs(ip_hdr->ip_len));
    fprintf(stderr, "\tid: %d\n", ntohs(ip_hdr->ip_id));
    printf("\n\nfinished print ip hdr.\n");
    /*1. if it's for me */

    if (ip_dst == iface->ip)
    {
        printf("This is for me, but i have implemented how to handle it\n");
        /*2. if it's ICMP echo req, send echo reply */

        /*3. if it's tcp/udp, send ICMP port unreachable */
    }
    else
    {
        struct in_addr ip_addr;
        ip_addr.s_addr = ip_dst;

        struct sr_rt *rt = sr_rt_lpm_lookup(sr, ip_addr);
        printf("finished finding rt\n");
        if (lpm)
        {
            struct sr_if *t_iface = sr_get_interface(sr, rt->interface);
            if (t_iface)
            {
                printf("There is a match, about to check arp cache\n");
            }
        }
        else
        {
            printf("There is no match, should send icmp net unreachable\n");
        }
    }
    /*4. if it's not for me */
    /*5. check routing table, perform lightweight packet marking */
    /*6. if there isn't a match */
    /*7. send ICMP net unreachable*/
    /*8. if there is a match */
    /*9. check if there is a arp cache exists */
    /*10. if no arp cache */
    /*11. send arp request and resent >5 times */
    /*12. if exists arp cache */
    /*13. send frame to next hope */
}