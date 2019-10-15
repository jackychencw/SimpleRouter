/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */
  if(len < (sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr))){
    printf("Ethernet frame too short");
    return;
  }
  uint16_t packet_type = ethertype(packet);
  switch (packet_type)
  {
  case ethertype_arp:
    printf("This is an arp packet\n");
    print_hdr_arp(packet);
    break;
  case ethertype_ip:
    printf("This is an ip packet\n");
    /* TODO print_hdr_ip(packet);*/
    /* Ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    /* IP header */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t));

    /* Sanity check */
    uint16_t ip_sum_check = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    if(ip_sum_check != cksum(ip_hdr, sizeof(sr_ip_hdr_t))){
      printf("IP checksum incorrect");
      return;
    }
    ip_hdr->ip_sum = ip_sum_check;

    struct sr_if *get_itf = sr_get_interface(sr, interface);
    struct sr_arpcache *arp_cache = &sr->cache;

    if(ip_hdr->ip_ttl <= 1){
      /* ICMP header */
      unsigned int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
      uint8_t *packet_icmp = (uint8_t *)malloc(icmp_len);
      /* Ethernet header */
      sr_ethernet_hdr_t *eth_hdr_upd = (sr_ethernet_hdr_t *)packet_icmp;
      memcpy(eth_hdr_upd->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(eth_hdr_upd->ether_shost, get_itf->addr, ETHER_ADDR_LEN);
      eth_hdr_upd->ether_type = eth_hdr->ether_type;
      /* IP header */
      sr_ip_hdr_t *ip_hdr_upd = (sr_ip_hdr_t *)((unsigned char *)packet_icmp + sizeof(sr_ethernet_hdr_t));
      ip_hdr_upd->ip_hl = ip_hdr->ip_hl;
      ip_hdr_upd->ip_v = ip_hdr->ip_v;
      ip_hdr_upd->ip_tos = ip_hdr->ip_tos;
      ip_hdr_upd->ip_len = htons(icmp_len - sizeof(sr_ethernet_hdr_t));
      ip_hdr_upd->ip_id = 0;
      ip_hdr_upd->ip_off = htons(IP_DF);
      ip_hdr_upd->ip_ttl = INIT_TTL;
      ip_hdr_upd->ip_p = ip_protocol_icmp;
      ip_hdr_upd->ip_sum = 0;
      uint16_t ip_sum_upd = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      ip_hdr_upd->ip_sum = ip_sum_upd;
      ip_hdr_upd->ip_src = get_itf->ip;
      ip_hdr_upd->ip_dst = ip_hdr->ip_src;
      /* ICMP header */
      sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((unsigned char *)packet_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      icmp_hdr->icmp_type = 11;
      icmp_hdr->icmp_code = 0;
      icmp_hdr->icmp_sum = 0;
      uint16_t icmp_sum_upd = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
      icmp_hdr->icmp_sum = icmp_sum_upd;
      icmp_hdr->unused = 0;
      icmp_hdr->next_mtu = 0;
      memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);

      struct sr_arpentry *arp_entry = sr_arpcache_lookup(arp_cache, ip_hdr->ip_src);
      if(arp_entry){
        sr_send_packet(sr, packet_icmp, icmp_len, get_itf->name);
        free(packet_icmp);
      }else{
        struct sr_arpreq *arp_req = sr_arpcache_queuereq(arp_cache, ip_hdr->ip_src, packet_icmp, icmp_len, get_itf->name);
        handle_arpreq(sr, arp_req);
      }
      return;
    }

    struct sr_if *if_itf = 0;
    struct sr_if *itf_list = sr->if_list;
    uint32_t dst_ip = ip_hdr->ip_dst;
    while(itf_list){
      if(itf_list->ip == dst_ip){
        if_itf = itf_list;
      }
      itf_list = itf_list->next;
    } 
    uint8_t ip_p_check = ip_hdr->ip_p;
    struct sr_rt *rtable = sr->routing_table;

    if(if_itf){
      if(ip_p_check == ip_protocol_icmp){
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        if(icmp_hdr->icmp_type == 8){
          struct sr_rt *lm_entry = lpm_entry(rtable, ip_hdr->ip_src);
          if(lm_entry){
            struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, lm_entry->gw.s_addr);
            struct sr_if *lm_entry_itf = sr_get_interface(sr, lm_entry->interface);
            if(arp_entry){
              /* Ethernet header */
              memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
              memcpy(eth_hdr->ether_shost, lm_entry_itf->addr, ETHER_ADDR_LEN);
              /* IP header */
              ip_hdr->ip_off = htons(IP_DF);
              ip_hdr->ip_ttl = INIT_TTL;
              ip_hdr->ip_sum = 0;
              uint16_t ip_sum_check = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
              ip_hdr->ip_sum = ip_sum_check;
              uint32_t ip_dst_upd = ip_hdr->ip_src;
              ip_hdr->ip_src = ip_hdr->ip_dst;
              ip_hdr->ip_dst = ip_dst_upd;
              /* ICMP header */
              icmp_hdr->icmp_type = 0;
              icmp_hdr->icmp_code = 0;
              icmp_hdr->icmp_sum = 0;
              uint16_t icmp_sum_check = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
              icmp_hdr->icmp_sum = icmp_sum_check;
              sr_send_packet(sr, packet, len, lm_entry_itf->name);
              return;
            }else{
              /* Ethernet header */
              memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
              memcpy(eth_hdr->ether_shost, get_itf->addr, ETHER_ADDR_LEN);
              /* IP header */
              ip_hdr->ip_off = htons(IP_DF);
              ip_hdr->ip_ttl = INIT_TTL;
              ip_hdr->ip_sum = 0;
              uint16_t ip_sum_check = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
              ip_hdr->ip_sum = ip_sum_check;
              uint32_t ip_dst_upd = ip_hdr->ip_src;
              ip_hdr->ip_src = ip_hdr->ip_dst;
              ip_hdr->ip_dst = ip_dst_upd;
              /* ICMP header */
              icmp_hdr->icmp_type = 0;
              icmp_hdr->icmp_code = 0;
              icmp_hdr->icmp_sum = 0;
              uint16_t icmp_sum_check = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
              icmp_hdr->icmp_sum = icmp_sum_check;
              sr_send_packet(sr, packet, len, lm_entry_itf->name);
              struct sr_arpreq *arp_req = sr_arpcache_queuereq(arp_cache, ip_hdr->ip_dst, packet, len, lm_entry_itf->name);
              handle_arpreq(sr, arp_req);
              return;
            }
          }else{
            printf("No longest prefix match entry");
            return;
          }
        }else{
          printf("Not ICMP type8");
        }
      }else{
        printf("TCP/UDP request");
        struct sr_rt *lm_entry = lpm_entry(rtable, ip_hdr->ip_src);
        if(lm_entry){
          struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, lm_entry->gw.s_addr);
          struct sr_if *lm_entry_itf = sr_get_interface(sr, lm_entry->interface);
          if(arp_entry){
            /* ICMP header */
            int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *packet_icmp = (uint8_t *)malloc(icmp_len);
            /* Ethernet header */
            sr_ethernet_hdr_t *eth_hdr_upd = (sr_ethernet_hdr_t *)packet_icmp;
            memcpy(eth_hdr_upd->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(eth_hdr_upd->ether_shost, if_itf->addr, ETHER_ADDR_LEN);
            eth_hdr_upd->ether_type = eth_hdr->ether_type;
            /* IP header */
            sr_ip_hdr_t *ip_hdr_upd = (sr_ip_hdr_t *)((unsigned char *)packet_icmp + sizeof(sr_ethernet_hdr_t));
            ip_hdr_upd->ip_hl = ip_hdr->ip_hl;
            ip_hdr_upd->ip_v = ip_hdr->ip_v;
            ip_hdr_upd->ip_tos = ip_hdr->ip_tos;
            ip_hdr_upd->ip_len = htons(icmp_len - sizeof(sr_ethernet_hdr_t));
            ip_hdr_upd->ip_id = 0;
            ip_hdr_upd->ip_off = htons(IP_DF);
            ip_hdr_upd->ip_ttl = INIT_TTL;
            ip_hdr_upd->ip_p = ip_protocol_icmp;
            ip_hdr_upd->ip_sum = 0;
            uint16_t ip_sum_upd = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
            ip_hdr_upd->ip_sum = ip_sum_upd;
            ip_hdr_upd->ip_src = if_itf->ip;
            ip_hdr_upd->ip_dst = ip_hdr->ip_src;
            /* ICMP header */
            sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((unsigned char *)packet_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_type = 3;
            icmp_hdr->icmp_code = 3;
            icmp_hdr->icmp_sum = 0;
            uint16_t icmp_sum_upd = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
            icmp_hdr->icmp_sum = icmp_sum_upd;
            icmp_hdr->unused = 0;
            icmp_hdr->next_mtu = 0;
            memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);

            sr_send_packet(sr, packet_icmp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lm_entry_itf->name);
            free(packet_icmp);
            return;
          }else{
            /* ICMP header */
            int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *packet_icmp = (uint8_t *)malloc(icmp_len);
            /* Ethernet header */
            sr_ethernet_hdr_t *eth_hdr_upd = (sr_ethernet_hdr_t *)packet_icmp;
            memcpy(eth_hdr_upd->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(eth_hdr_upd->ether_shost, if_itf->addr, ETHER_ADDR_LEN);
            eth_hdr_upd->ether_type = eth_hdr->ether_type;
            /* IP header */
            sr_ip_hdr_t *ip_hdr_upd = (sr_ip_hdr_t *)((unsigned char *)packet_icmp + sizeof(sr_ethernet_hdr_t));
            ip_hdr_upd->ip_hl = ip_hdr->ip_hl;
            ip_hdr_upd->ip_v = ip_hdr->ip_v;
            ip_hdr_upd->ip_tos = ip_hdr->ip_tos;
            ip_hdr_upd->ip_len = htons(icmp_len - sizeof(sr_ethernet_hdr_t));
            ip_hdr_upd->ip_id = 0;
            ip_hdr_upd->ip_off = htons(IP_DF);
            ip_hdr_upd->ip_ttl = INIT_TTL;
            ip_hdr_upd->ip_p = ip_protocol_icmp;
            ip_hdr_upd->ip_sum = 0;
            uint16_t ip_sum_upd = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
            ip_hdr_upd->ip_sum = ip_sum_upd;
            ip_hdr_upd->ip_src = if_itf->ip;
            ip_hdr_upd->ip_dst = ip_hdr->ip_src;
            /* ICMP header */
            sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((unsigned char *)packet_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_type = 3;
            icmp_hdr->icmp_code = 3;
            icmp_hdr->icmp_sum = 0;
            uint16_t icmp_sum_upd = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
            icmp_hdr->icmp_sum = icmp_sum_upd;
            icmp_hdr->unused = 0;
            icmp_hdr->next_mtu = 0;
            memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);

            struct sr_arpreq *arp_req = sr_arpcache_queuereq(arp_cache, ip_hdr->ip_src, packet_icmp, 
                                    sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lm_entry_itf->name);
            handle_arpreq(sr, arp_req);
            return;
          }
        }else{
          printf("No longest prefix match entry");
          return;
        }
      }
    }else{
      /* Sanity check */
      if(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) > len){
        printf("Packet length too short");
        return;
      }
      struct sr_rt *lm_entry = lpm_entry(rtable, ip_hdr->ip_dst);
      if(lm_entry){
        struct sr_if *lm_entry_itf = sr_get_interface(sr, lm_entry->interface);
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, lm_entry->gw.s_addr);
        if(arp_entry){
          ip_hdr->ip_ttl--;
          ip_hdr->ip_sum = 0;
          uint16_t ip_sum_upd = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
          ip_hdr->ip_sum = ip_sum_upd;
          memcpy(eth_hdr->ether_shost, lm_entry_itf->addr, ETHER_ADDR_LEN);
          memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
          sr_send_packet(sr, packet, len, lm_entry_itf->name);
          free(arp_entry);
          return;
        }else{
          ip_hdr->ip_ttl--;
          ip_hdr->ip_sum = 0;
          uint16_t ip_sum_upd = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
          ip_hdr->ip_sum = ip_sum_upd;
          struct sr_arpreq *arp_req = sr_arpcache_queuereq(arp_cache, ip_hdr->ip_dst, packet, len, lm_entry_itf->name);
          handle_arpreq(sr, arp_req);
          return;
        }
    }else{
      struct sr_rt *lm_entry = lpm_entry(rtable, ip_hdr->ip_src);
      if(lm_entry){
        struct sr_if *lm_entry_itf = sr_get_interface(sr, lm_entry->interface);
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, lm_entry->gw.s_addr);
        if(arp_entry){
          /* ICMP header */
            int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *packet_icmp = (uint8_t *)malloc(icmp_len);
            /* Ethernet header */
            sr_ethernet_hdr_t *eth_hdr_upd = (sr_ethernet_hdr_t *)packet_icmp;
            memcpy(eth_hdr_upd->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(eth_hdr_upd->ether_shost, lm_entry_itf->addr, ETHER_ADDR_LEN);
            eth_hdr_upd->ether_type = eth_hdr->ether_type;
            /* IP header */
            sr_ip_hdr_t *ip_hdr_upd = (sr_ip_hdr_t *)((unsigned char *)packet_icmp + sizeof(sr_ethernet_hdr_t));
            ip_hdr_upd->ip_hl = ip_hdr->ip_hl;
            ip_hdr_upd->ip_v = ip_hdr->ip_v;
            ip_hdr_upd->ip_tos = ip_hdr->ip_tos;
            ip_hdr_upd->ip_len = htons(icmp_len - sizeof(sr_ethernet_hdr_t));
            ip_hdr_upd->ip_id = 0;
            ip_hdr_upd->ip_off = htons(IP_DF);
            ip_hdr_upd->ip_ttl = INIT_TTL;
            ip_hdr_upd->ip_p = ip_protocol_icmp;
            ip_hdr_upd->ip_sum = 0;
            uint16_t ip_sum_upd = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
            ip_hdr_upd->ip_sum = ip_sum_upd;
            ip_hdr_upd->ip_src = lm_entry_itf->ip;
            ip_hdr_upd->ip_dst = ip_hdr->ip_src;
            /* ICMP header */
            sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((unsigned char *)packet_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_type = 3;
            icmp_hdr->icmp_code = 0;
            icmp_hdr->icmp_sum = 0;
            uint16_t icmp_sum_upd = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
            icmp_hdr->icmp_sum = icmp_sum_upd;
            icmp_hdr->unused = 0;
            icmp_hdr->next_mtu = 0;
            memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);

            sr_send_packet(sr, packet_icmp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), lm_entry_itf->name);
            free(packet_icmp);
            return;
        }
      else{
        int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *packet_icmp = (uint8_t *)malloc(icmp_len);
            /* Ethernet header */
            sr_ethernet_hdr_t *eth_hdr_upd = (sr_ethernet_hdr_t *)packet_icmp;
            memcpy(eth_hdr_upd->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(eth_hdr_upd->ether_shost, lm_entry_itf->addr, ETHER_ADDR_LEN);
            eth_hdr_upd->ether_type = eth_hdr->ether_type;
            /* IP header */
            sr_ip_hdr_t *ip_hdr_upd = (sr_ip_hdr_t *)((unsigned char *)packet_icmp + sizeof(sr_ethernet_hdr_t));
            ip_hdr_upd->ip_hl = ip_hdr->ip_hl;
            ip_hdr_upd->ip_v = ip_hdr->ip_v;
            ip_hdr_upd->ip_tos = ip_hdr->ip_tos;
            ip_hdr_upd->ip_len = htons(icmp_len - sizeof(sr_ethernet_hdr_t));
            ip_hdr_upd->ip_id = 0;
            ip_hdr_upd->ip_off = htons(IP_DF);
            ip_hdr_upd->ip_ttl = INIT_TTL;
            ip_hdr_upd->ip_p = ip_protocol_icmp;
            ip_hdr_upd->ip_sum = 0;
            uint16_t ip_sum_upd = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
            ip_hdr_upd->ip_sum = ip_sum_upd;
            ip_hdr_upd->ip_src = lm_entry_itf->ip;
            ip_hdr_upd->ip_dst = ip_hdr->ip_src;
            /* ICMP header */
            sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((unsigned char *)packet_icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_type = 3;
            icmp_hdr->icmp_code = 0;
            icmp_hdr->icmp_sum = 0;
            uint16_t icmp_sum_upd = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
            icmp_hdr->icmp_sum = icmp_sum_upd;
            icmp_hdr->unused = 0;
            icmp_hdr->next_mtu = 0;
            memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);

            struct sr_arpreq *arp_req = sr_arpcache_queuereq(arp_cache, ip_hdr->ip_src, packet, len, lm_entry_itf->name);
            handle_arpreq(sr, arp_req);
            return;
          }
        }else{
        printf("No longest prefix match entry");
        return;
        }
      }
    }
    return;
  }
} /* end sr_ForwardPacket */

struct sr_rt *lpm_entry(struct sr_rt *rtable, uint32_t dst_ip){
  uint32_t lm = 0;
  struct sr_rt *lm_entry = NULL;
  while(rtable){
    if(((rtable->dest.s_addr & rtable->mask.s_addr) == (dst_ip & rtable->mask.s_addr)) && (rtable->mask.s_addr > lm)){
        lm = rtable->mask.s_addr;
        lm_entry = rtable;
    }
    rtable = rtable->next;
  }
  return lm_entry;
}