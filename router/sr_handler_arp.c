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
#include "sr_handler_icmp.h"

void sr_send_5_arp_req(struct sr_instance *sr, struct sr_arpreq *request)
{
    time_t now = time(0);
    time_t sent = request->sent;
    uint32_t times_sent = request->times_sent;
    pthread_mutex_lock(&sr->cache.lock);
    int dest_ip = request->ip;
    struct sr_if *tar_interface = sr_rt_lookup_iface(sr, dest_ip);
    if (difftime(now, sent) > 1.0)
    {
        struct sr_packet *packet;
        for (packet = request->packets; packet; packet = packet->next)
        {
            struct sr_if *src_interface = sr_get_interface(sr, packet->iface);
            if (times_sent >= 5)
            {
                sr_handle_icmp_t3(sr, (uint8_t *)packet, icmp_dest_unreachable_type, icmp_host_unreachable_code, src_interface);
                sr_arpreq_destroy(&sr->cache, request);
            }
            else
            {
                if (!tar_interface)
                {
                    printf("didnt' find interface\n");
                    return;
                }
                request->sent = time(0);
                request->times_sent += 1;

                unsigned int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
                uint8_t *packet = (uint8_t *)malloc(packet_size);
                sr_ethernet_hdr_t *eth_hder = (sr_ethernet_hdr_t *)packet;
                sr_arp_hdr_t *arp_hder = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
                memset(eth_hder->ether_dhost, 0xff, ETHER_ADDR_LEN);
                memcpy(eth_hder->ether_shost, src_interface->addr, ETHER_ADDR_LEN);
                eth_hder->ether_type = htons(ethertype_arp);

                arp_hder->ar_hrd = htons(arp_hrd_ethernet);
                arp_hder->ar_pro = htons(ethertype_ip);
                arp_hder->ar_hln = ETHER_ADDR_LEN;
                /* Deault ip version is ipv4 */
                arp_hder->ar_pln = 4;
                arp_hder->ar_op = htons(arp_op_request);
                memcpy(arp_hder->ar_sha, src_interface->addr, ETHER_ADDR_LEN);
                arp_hder->ar_sip = src_interface->ip;
                memset(arp_hder->ar_tha, 0xff, ETHER_ADDR_LEN);
                arp_hder->ar_tip = dest_ip;
                sr_send_packet(sr, packet, packet_size, src_interface->name);
            }
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

int send_arp_packet(struct sr_instance *sr, uint8_t *sha, uint32_t sip, uint8_t *tha, uint32_t tip, unsigned short opcode, struct sr_if *interface)
{
    printf("Creating an arp packet...\n");
    unsigned int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *packet = (uint8_t *)malloc(packet_size);
    sr_ethernet_hdr_t *eth_hder = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *arp_hder = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    memcpy(eth_hder->ether_dhost, tha, ETHER_ADDR_LEN);
    memcpy(eth_hder->ether_shost, sha, ETHER_ADDR_LEN);
    eth_hder->ether_type = htons(ethertype_arp);

    arp_hder->ar_hrd = htons(arp_hrd_ethernet);
    arp_hder->ar_pro = htons(ethertype_ip);
    arp_hder->ar_hln = ETHER_ADDR_LEN;
    /* Deault ip version is ipv4 */
    arp_hder->ar_pln = 4;
    arp_hder->ar_op = htons(arp_op_reply);
    memcpy(arp_hder->ar_sha, sha, ETHER_ADDR_LEN);
    arp_hder->ar_sip = sip;
    memcpy(arp_hder->ar_tha, tha, ETHER_ADDR_LEN);
    arp_hder->ar_tip = tip;
    int res = sr_send_packet(sr, packet, packet_size, interface->name);
    print_hdrs(packet, packet_size);
    return res;
}

void sr_handle_arp_op_req(struct sr_instance *sr, sr_ethernet_hdr_t *eth_hder, sr_arp_hdr_t *arp_hder, struct sr_if *interface)
{
    printf("Simple router handling arp request...\n");
    sr_arpcache_insert(&sr->cache, arp_hder->ar_sha, arp_hder->ar_sip);
    send_arp_packet(sr,
                    interface->addr,  /* sha */
                    interface->ip,    /* sip */
                    arp_hder->ar_sha, /* tha */
                    arp_hder->ar_sip, /* tip */
                    arp_op_reply,
                    interface);
}

/* When receive an reply, fidn all cache that's related to this sha and send request */
void sr_handle_arp_op_rep(struct sr_instance *sr,
                          sr_ethernet_hdr_t *ethernet_hdr,
                          sr_arp_hdr_t *arp_hdr,
                          struct sr_if *iface)
{
    printf("Simple router handling arp reply...\n");
    if (iface->ip == arp_hdr->ar_tip)
    {
        pthread_mutex_lock(&sr->cache.lock);
        struct sr_arpreq *request = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
        if (request)
        {
            struct sr_packet *packet;
            for (packet = request->packets; packet; packet = packet->next)
            {
                printf("sending packet\n");
                sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)packet->buf;
                memcpy(new_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                memcpy(new_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
                sr_send_packet(sr, packet->buf, packet->len, packet->iface);
            }
            sr_arpreq_destroy(&sr->cache, request);
        }
    }
    pthread_mutex_unlock(&sr->cache.lock);
}

void sr_handle_arp(struct sr_instance *sr,
                   uint8_t *packet,
                   unsigned int len,
                   struct sr_if *iface)
{
    sr_ethernet_hdr_t *ethernet_hdr = get_ethernet_hdr(packet);
    sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);
    /* print_hdrs(packet, len); */

    /* Do sanity check on arp packet */
    if (!arp_sanity_check(len))
    {
        fprintf(stderr, "Packet doesn't meet minimum length requirement.\n");
        return;
    }

    uint16_t op_code = ntohs(arp_hdr->ar_op);
    switch (op_code)
    {
    case arp_op_request:
        printf("Sensed [ARP request], handling ...\n\n");
        /* Construct an arp reply and send it back. */
        sr_handle_arp_op_req(sr, ethernet_hdr, arp_hdr, iface);
        break;
    case arp_op_reply:
        printf("Sensed [ARP reply], handling ...\n\n");
        /* Cache it, go through request queue and send it back. */
        sr_handle_arp_op_rep(sr, ethernet_hdr, arp_hdr, iface);
        break;
    default:
        fprintf(stderr, "Invalid packet op code.\n");
        return;
    }
}