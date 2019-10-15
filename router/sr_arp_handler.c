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

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request)
{
    printf("\n\nhandle_arpreq\n\n");
    time_t now = time(0);
    time_t sent = request->sent;
    uint32_t times_sent = request->times_sent;
    pthread_mutex_lock(&sr->cache.lock);

    if (difftime(now, sent) > 1.0)
    {
        if (times_sent >= 5)
        {
            /* TODO: Send icmp host unreachable to source addr of all pkts waiting on 
            this request*/
            sr_arpreq_destroy(&sr->cache, request);
        }
        else
        {
            /* sr_send_arpreq(sr, request->ip);*/
            request->sent = time(0);
            request->times_sent += 1;
        }
    }
    pthread_mutex_unlock(&sr->cache.lock);
}

/*--

   The ARP reply processing code should move entries from the ARP request
   queue to the ARP cache:

   # When servicing an arp reply that gives us an IP->MAC mapping
   req = arpcache_insert(ip, mac)

   if req:
       send all packets on the req->packets linked list
       arpreq_destroy(req)

   --*/
void handle_arprep(struct sr_instance *sr,
                   sr_arp_hdr_t *arp_hdr,
                   struct sr_if *iface)
{
    /* Find request by id */
    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache,
                                               arp_hdr->ar_sha,
                                               arp_hdr->ar_sip);
    if (req)
    {
        printf("\n\n\nHandling arp reply\n\n\n");
        struct sr_packet *packet = req->packets;
        while (packet)
        {
            struct sr_packet *next = packet->next;
            uint8_t *buf = packet->buf;
            sr_send_packet(sr, buf, packet->len, iface->name);
            packet = next;
        }
    }
    sr_arpreq_destroy(&sr->cache, req);
}

int sr_send_arprep(struct sr_instance *sr,
                   sr_ethernet_hdr_t *origin_ethernet_hder,
                   sr_arp_hdr_t *origin_arp_hder,
                   struct sr_if *iface)
{
    printf("Sr send arp reply...\n");
    unsigned int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *packet = (uint8_t *)malloc(packet_size);
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
    memcpy(rep_arp_hder->ar_tha, origin_arp_hder->ar_sha, ETHER_ADDR_LEN);
    rep_arp_hder->ar_tip = origin_arp_hder->ar_sip;

    printf("Following data for reply packet. \n");
    print_hdrs(packet, packet_size);

    int res = sr_send_packet(sr, packet, packet_size, iface->name);
    return res;
}

int sr_send_arpreq(struct sr_instance *sr,
                   sr_ethernet_hdr_t *ethernet_hdr,
                   sr_arp_hdr_t *arp_hdr,
                   struct sr_if *iface)
{
    printf("Sr send arp req\n");
    unsigned int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *packet = (uint8_t *)malloc(packet_size);

    sr_ethernet_hdr_t *req_eth_hder = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *req_arp_hder = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /*
    Find interface to destination ip
    */
    struct sr_if *interface = sr_rt_lookup(sr, 1 /* TODO: Replace this */);
    uint8_t *origin_sha = arp_hdr->ar_sha;
    uint8_t *origin_tha = arp_hdr->ar_tha;

    memset(req_eth_hder->ether_dhost, origin_sha, ETHER_ADDR_LEN);
    memcpy(req_eth_hder->ether_shost, interface->addr, ETHER_ADDR_LEN);
    req_eth_hder->ether_type = ntohs(ethertype_arp);

    req_arp_hder->ar_hrd = arp_hdr->ar_hrd;
    req_arp_hder->ar_pro = arp_hdr->ar_pro;
    req_arp_hder->ar_hln = arp_hdr->ar_hln;
    req_arp_hder->ar_pln = arp_hdr->ar_pln;
    req_arp_hder->ar_op = htons(arp_op_reply);
    memcpy(req_arp_hder->ar_sha, &iface->addr, ETHER_ADDR_LEN);
    req_arp_hder->ar_sip = iface->ip;
    memcpy(req_arp_hder->ar_tha, origin_sha, ETHER_ADDR_LEN);
    req_arp_hder->ar_tip = arp_hdr->ar_sip;

    int res = sr_send_packet(sr, packet, packet_size, iface->name);

    return res;
}

void sr_handle_arp(struct sr_instance *sr,
                   uint8_t *packet,
                   unsigned int len,
                   struct sr_if *iface)
{
    sr_ethernet_hdr_t *ethernet_hdr = get_ethernet_hdr(packet);
    sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);
    print_hdrs(packet, len);
    if (!arp_sanity_check(len))
    {
        fprintf(stderr, "Packet doesn't meet minimum length requirement.\n");
        return;
    }

    uint16_t op_code = ntohs(arp_hdr->ar_op);

    switch (op_code)
    {
    case arp_op_request:
        /* Construct an arp reply and send it back. */
        printf("Sensed [ARP request], handling ...\n\n");
        sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        sr_send_arprep(sr, ethernet_hdr, arp_hdr, iface);
        break;
    case arp_op_reply:
        /* Cache it, go through request queue and send it back. */
        printf("Sensed [ARP reply], handling ...\n\n");
        sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        /* TODO: handle arp op reply. */
        break;
    default:
        fprintf(stderr, "Invalid packet op code.\n");
        return;
    }
}