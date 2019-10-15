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

uint8_t *create_arp_packet(uint8_t *sha, uint32_t sip, uint8_t *tha, uint32_t tip, unsigned short opcode)
{
    printf("Creating an arp packet...\n");
    unsigned int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *packet = (uint8_t *)malloc(packet_size);
    sr_ethernet_hdr_t *eth_hder = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *arp_hder = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    add_ethernet_header(eth_hder, tha, sha, ethertype_arp);

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

    return packet;
}

void sr_handle_arp_op_req(struct sr_instance *sr, sr_ethernet_hdr_t *eth_hder, sr_arp_hdr_t *arp_hder, struct sr_if *interface)
{
    unsigned int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *reply_packet = create_arp_packet(interface->addr,  /* sha */
                                              interface->ip,    /* sip */
                                              arp_hder->ar_sha, /* tha */
                                              arp_hder->ar_sip, /* tip */
                                              arp_op_reply);
    sr_send_packet(sr, reply_packet, packet_size, interface->name);
}

/* When receive an reply, fidn all cache that's related to this sha and send request */
void sr_handle_arp_op_rep(struct sr_instance *sr,
                          sr_ethernet_hdr_t *ethernet_hdr,
                          sr_arp_hdr_t *arp_hdr,
                          struct sr_if *iface)
{
    printf("Simple router handling arp request...\n");
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
    if (req)
    {
        struct sr_packet *packet = req->packets;
        while (packet)
        {
            struct sr_packet *next = packet->next;
            sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)packet->buf;

            /* Replace destination host to reply's sha */
            memcpy(new_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet->buf, packet->len, packet->iface);
            packet = next;
        }
    }
    sr_arpreq_destroy(&sr->cache, req);
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