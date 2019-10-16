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

int sr_handle_icmp_t3(struct sr_instance *sr,
                      uint8_t *buf,
                      uint8_t icmp_type,
                      uint8_t icmp_code,
                      struct sr_if *rec_iface)
{
    printf("handling icmp t3\n");
    unsigned int packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *packet = (uint8_t *)malloc(packet_size);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    sr_ethernet_hdr_t *target_eth_hdr = (sr_ethernet_hdr_t *)buf;
    sr_ip_hdr_t *target_ip_hdr = get_ip_hdr(buf);
    struct sr_if *iface = sr_rt_lookup_iface(sr, target_ip_hdr->ip_src);

    add_ethernet_header(eth_hdr, target_eth_hdr->ether_shost, iface->addr, ethertype_ip);
    add_ip_header(ip_hdr, packet_size,
                  target_ip_hdr->ip_hl,
                  target_ip_hdr->ip_v,
                  target_ip_hdr->ip_tos,
                  target_ip_hdr->ip_p,
                  iface->ip,
                  target_ip_hdr->ip_src);
    add_icmp_t3_header(icmp_t3_hdr, icmp_type, icmp_code, (uint8_t *)target_ip_hdr);
    print_hdrs(packet, packet_size);
    int res = sr_send_packet(sr, packet, packet_size, iface->name);
    return res;
}

int sr_handle_icmp_reply(struct sr_instance *sr, uint8_t *buf, unsigned int buf_size, uint8_t type, uint8_t code, struct sr_if *iface)
{
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buf;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    struct sr_if *target_iface = sr_rt_lookup_iface(sr, ip_hdr->ip_src);

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, target_iface->addr, ETHER_ADDR_LEN);
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hdr->ip_src = iface->ip;
    add_icmp_header(icmp_hdr, type, code);
    int res = sr_send_packet(sr, buf, buf_size, target_iface->name);
    printf("Echo reply handled.\n");
    return res;
}

void sr_handle_icmp(
    struct sr_instance *sr,
    uint8_t *packet,
    unsigned int len,
    struct sr_if *iface,
    uint8_t type,
    uint8_t code)
{
    switch (type)
    {
    case (icmp_dest_unreachable_type):
        printf("ICMP destination unreachable, handling.\n");
        sr_handle_icmp_t3(sr, packet, type, code, iface);
        break;
    case (icmp_echo_reply_type):
        printf("ICMP echo reply, handling.\n");
        sr_handle_icmp_reply(sr, packet, len, type, code, iface);
        break;
    case (icmp_time_exceed_type):
        printf("ICMP echo reply, handling.\n");
        sr_handle_icmp_reply(sr, packet, len, type, code, iface);
        break;
    default:
        printf("no valid type\n");
        return;
    }
}