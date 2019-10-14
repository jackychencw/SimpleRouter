#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_helpers.h"

int sr_send_arprep(struct sr_instance *sr,
                   sr_ethernet_hdr_t *origin_ethernet_hder,
                   sr_arp_hdr_t *origin_arp_hder,
                   struct sr_if *iface)
{
    printf("Sr send arp req\n");
    unsigned int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *packet = (uint8_t *)malloc(packet_size);

    /* 
  First assign pointer to ethernet header, then shift arp header 
  by size of ethernet header
  */
    sr_ethernet_hdr_t *rep_eth_hder = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *rep_arp_hder = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    memcpy(rep_eth_hder->ether_dhost, origin_ethernet_hder->ether_shost, ETHER_ADDR_LEN);
    memcpy(rep_eth_hder->ether_shost, iface->addr, ETHER_ADDR_LEN);
    rep_eth_hder->ether_type = ntohs(ethertype_arp);

    rep_arp_hder->ar_hrd = origin_arp_hder->ar_hrd;
    rep_arp_hder->ar_pro = origin_arp_hder->ar_pro;
    rep_arp_hder->ar_hln = origin_arp_hder->ar_hln;
    rep_arp_hder->ar_pln = origin_arp_hder->ar_pln;
    rep_arp_hder->ar_op = htons(arp_op_reply);
    memcpy(rep_arp_hder->ar_sha, iface->addr, ETHER_ADDR_LEN);
    rep_arp_hder->ar_sip = iface->ip;
    memcpy(rep_arp_hder->ar_tha, origin_arp_hder->ar_tha, ETHER_ADDR_LEN);
    rep_arp_hder->ar_tip = origin_arp_hder->ar_sip;

    int res = sr_send_packet(sr, packet, packet_size, iface->name);
    return res;
}

int sr_send_arpreq(struct sr_instance *sr, uint32_t destination)
{
    /*
    unsigned int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *packet = (uint8_t *)malloc(packet_size);

    sr_ethernet_hdr_t *ethernet_hder = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *req_arp_hder = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    */

    /* 
    struct sr_if *interface = sr_rt_lookup(sr, destination);

    
    memset(ethernet_hder->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(ethernet_hder->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);
    ethernet_hder->ether_type = ntohs(ethertype_arp);

    req_arp_hder->ar_hrd = origin_arp_hder->ar_hrd;
    req_arp_hder->ar_pro = origin_arp_hder->ar_pro;
    req_arp_hder->ar_hln = origin_arp_hder->ar_hln;
    req_arp_hder->ar_pln = origin_arp_hder->ar_pln;
    req_arp_hder->ar_op = htons(arp_op_reply);
    memcpy(rep_arp_hder->ar_sha, iface->addr, ETHER_ADDR_LEN);
    rep_arp_hder->ar_sip = iface->ip;
    memcpy(rep_arp_hder->ar_tha, origin_arp_hder->ar_tha, ETHER_ADDR_LEN);
    rep_arp_hder->ar_tip = origin_arp_hder->ar_sip;

    int res = sr_send_packet(sr, packet, packet_size, iface->name);
    */

    return 1;
}

void sr_handle_arp(struct sr_instance *sr,
                   uint8_t *packet,
                   unsigned int len,
                   struct sr_if *sr_interface)
{
    sr_ethernet_hdr_t *ethernet_hdr = get_ethernet_hdr(packet);
    sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);

    if (!arp_sanity_check(len))
    {
        fprintf(stderr, "Packet doesn't meet minimum length requirement.\n");
        return;
    }

    uint16_t op_code = ntohs(arp_hdr->ar_op);

    switch (op_code)
    {
    case arp_op_request:
        /* Handle arp request*/
        printf("Sensed [ARP request], handling ...\n\n");
        sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        /* TODO: handle arp op request. */
        break;
    case arp_op_reply:
        /* Handle arp reply*/
        printf("Sensed [ARP reply], handling ...\n\n");
        /* TODO: handle arp op reply. */
        break;
    default:
        fprintf(stderr, "Invalid packet op code.\n");
        return;
    }
}

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