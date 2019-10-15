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

uint8_t *create_icmp_packet(uint8_t tha, uint8_t sha, struct sr_ip_hdr *dest_ip_hdr, uint8_t icmp_type, uint8_t icmp_code)
{
    unsigned int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *icmp_packet = (uint8_t *)malloc(icmp_len);
    sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(icmp_packet);
    sr_ip_hdr_t *ip_hdr = get_ip_hdr(icmp_packet);
    sr_icmp_t3_hdr_t *icmp_hdr = get_icmp_t3_hdr(icmp_packet);

    memset(eth_hdr->ether_dhost, tha, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, sha, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);

    ip_hdr->ip_hl = 4;
    ip_hdr->ip_id = 0;
    ip_hdr->ip_p = ip_protocol_icmp;
    ip_hdr->ip_tos = dest_ip_hdr->ip_tos;
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = INIT_TTL;
    ip_hdr->ip_v = dest_ip_hdr->ip_v;
    ip_hdr->ip_src = ;
    ip_hdr->ip_dst = tip;
    ip_hdr->ip_len = htons(icmp_len - sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->unused = 0;
    memcpy(icmp_hdr->data, dest_ip_hdr);

    return icmp_packet;
}

void handle_icmp_unreachable(struct sr_instance *sr)
{
    /*
    unsigned int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *icmp_packet = (uint8_t *)malloc(icmp_len);


    icmp_hdr.icmp_type = htons(icmp_dest_unreachable_type);
    icmp_hdr.icmp_code = code;
    icmp_hdr.unused = 0;
    icmp_hdr.icmp_sum = 0;


    error_ip_hdr = (struct sr_ip_hdr *)packet;
    ip_hdr.ip_hl = ICMP_IP_HDR_LEN;
    ip_hdr.ip_v = ip_version_4;
    ip_hdr.ip_tos = 0;
    ip_hdr.ip_id = error_ip_hdr->ip_id;
    ip_hdr.ip_off = htons(IP_DF);
    ip_hdr.ip_ttl = DEFAULT_TTL;
    ip_hdr.ip_p = ip_protocol_icmp;
    ip_hdr.ip_sum = 0;
    ip_hdr.ip_dst = error_ip_hdr->ip_src;
    dst = error_ip_hdr->ip_src;
    rt = sr_longest_prefix_match(sr, ip_in_addr(ip_hdr.ip_dst));
    if (rt == 0)
        return;

    interface = sr_get_interface(sr, (const char *)rt->interface);
    ip_hdr.ip_src = interface->ip;

    icmp_len = ip_ihl(error_ip_hdr) + ICMP_COPIED_DATAGRAM_DATA_LEN + sizeof(struct sr_icmp_hdr);
    total_len = icmp_len + ICMP_IP_HDR_LEN_BYTES;
    ip_hdr.ip_len = htons(total_len);

    ip_hdr.ip_sum = cksum(&ip_hdr, ICMP_IP_HDR_LEN_BYTES);

    new_pkt = malloc(total_len);
    memcpy(new_pkt, &ip_hdr, ICMP_IP_HDR_LEN_BYTES);
    memcpy(new_pkt + ICMP_IP_HDR_LEN_BYTES, &icmp_hdr, sizeof(struct sr_icmp_hdr));
    memcpy(new_pkt + ICMP_IP_HDR_LEN_BYTES + sizeof(struct sr_icmp_hdr),
           error_ip_hdr,
           ip_ihl(error_ip_hdr) + ICMP_COPIED_DATAGRAM_DATA_LEN);

    */
}

void handle_icmp_echo_reply(struct sr_instance *sr)
{
    /* Update the IP header fields.
    error_ip_hdr = (struct sr_ip_hdr *)packet;
    dst = error_ip_hdr->ip_src;
    error_ip_hdr->ip_src = error_ip_hdr->ip_dst;
    error_ip_hdr->ip_dst = dst;


    icmp_hdr_ptr = icmp_header(error_ip_hdr);
    icmp_hdr_ptr->icmp_sum = 0;
    icmp_hdr_ptr->icmp_code = code;
    icmp_hdr_ptr->icmp_type = type;


    total_len = ip_len(error_ip_hdr);
    new_pkt = malloc(total_len);
    memcpy(new_pkt, error_ip_hdr, total_len);

    icmp_len = total_len - ICMP_IP_HDR_LEN;
    */
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
        handle_icmp_unreachable(sr);
        break;
    case (icmp_echo_reply_type):
        printf("ICMP echo reply, handling.\n");
        handle_icmp_echo_reply(sr);
        break;
    default:
        Debug("ICMP type not recognized. %s\n", stderr);
        return
    }
}